/*
SPDX-License-Identifier: Apache-2.0
*/

// Package provisioning verifies Fabric history and issues join approvals
// without putting the provisioning authority's private key in node state.
package provisioning

import (
	"bytes"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/hyperledger/fabric-lib-go/bccsp"
	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric/core/ledger/kvledger"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/enrollment"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/provenance"
	"github.com/hyperledger/fabric/protoutil"
)

// VerifiedJoinHistory can only be obtained by verifying against a registry.
// The generic provenance verifier's result is not eligible for anchor issuance.
type VerifiedJoinHistory struct {
	history *provenance.VerifiedHistory
}

// Report returns the verification evidence for a registry-bound result.
func (v *VerifiedJoinHistory) Report() provenance.Report {
	if v == nil {
		return provenance.Report{}
	}
	return v.history.Report()
}

// VerifyJoinHistory binds complete history replay to the exact genesis anchor,
// transport policy and node identity already authenticated by Registry.
func VerifyJoinHistory(registry *enrollment.Registry, channel string, history []*cb.Block, targetBlockNumber uint64, crypto bccsp.BCCSP) (*VerifiedJoinHistory, error) {
	if registry == nil {
		return nil, errors.New("authenticated protected registry is required")
	}
	controller := registry.Controller(channel, crypto)
	if controller == nil {
		return nil, errors.New("channel is not enrolled for protected onboarding")
	}
	genesis, err := controller.GenesisBlock()
	if err != nil {
		return nil, fmt.Errorf("load independently authenticated genesis: %w", err)
	}
	if genesis.GetHeader() == nil {
		return nil, errors.New("authenticated genesis block has no header")
	}
	verified, err := provenance.VerifyHistory(provenance.Request{
		Network: registry.Network(), Node: registry.Node(), Channel: channel,
		TrustedGenesisHash: hex.EncodeToString(protoutil.BlockHeaderHash(genesis.GetHeader())),
		TargetBlockNumber:  targetBlockNumber, History: history,
		Policy: registry.TransportPolicy(), Crypto: crypto,
	})
	if err != nil {
		return nil, err
	}
	return &VerifiedJoinHistory{history: verified}, nil
}

// SignVerifiedOrdererJoinAnchor signs an orderer anchor only from a completed
// provenance verification and only with the corresponding policy signer.
func SignVerifiedOrdererJoinAnchor(verified *VerifiedJoinHistory, signer *mldsa.PrivateKey) ([]byte, error) {
	anchor, err := joinAnchorFromVerified(verified, signer)
	if err != nil {
		return nil, err
	}
	return signJoinAnchor(signer, enrollment.OrdererJoinAnchorDomain, anchor)
}

// SignVerifiedPeerSnapshotAnchor signs only a snapshot that was authenticated
// by an independently trusted exporter and copied to a private staging
// directory by VerifySnapshotExport.
func SignVerifiedPeerSnapshotAnchor(verified *VerifiedJoinHistory, export *VerifiedSnapshotExport, signer *mldsa.PrivateKey) ([]byte, error) {
	joinAnchor, err := joinAnchorFromVerified(verified, signer)
	if err != nil {
		return nil, err
	}
	if export == nil || export.history != verified || export.stageDir == "" || export.trust == nil {
		return nil, errors.New("verified staged snapshot export is required before peer snapshot approval")
	}
	root, err := os.OpenRoot(export.stageDir)
	if err != nil {
		return nil, fmt.Errorf("open verified staged snapshot: %w", err)
	}
	defer root.Close()
	signable, err := root.ReadFile(kvledger.SnapshotSignableMetadataFileName)
	if err != nil {
		return nil, err
	}
	additional, err := root.ReadFile(kvledger.SnapshotAdditionalMetadataFileName)
	if err != nil {
		return nil, err
	}
	evidenceBytes, err := root.ReadFile(SnapshotExportEvidenceFileName)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(signable, export.signable) || !bytes.Equal(additional, export.additional) ||
		!bytes.Equal(evidenceBytes, export.evidenceBytes) {
		return nil, errors.New("verified staged snapshot metadata or export evidence changed before signing")
	}
	evidence, err := verifySnapshotExportEvidence(evidenceBytes, export.trust.publicKey)
	if err != nil {
		return nil, err
	}
	metadata, err := decodeSnapshotMetadata(signable)
	if err != nil {
		return nil, err
	}
	if err := validateSnapshotExportBoundary(evidence, export.trust, joinAnchor, verified.Report(), metadata, signable, additional); err != nil {
		return nil, err
	}
	if err := verifySnapshotDirectory(root, evidence.PayloadFiles, SnapshotExportEvidenceFileName); err != nil {
		return nil, err
	}
	for name, digest := range evidence.PayloadFiles {
		if err := verifySnapshotFile(root, name, digest); err != nil {
			return nil, err
		}
	}
	if err := verifyNativeAdditionalMetadata(signable, additional); err != nil {
		return nil, err
	}
	anchor := enrollment.PeerSnapshotAnchor{
		JoinAnchor:             joinAnchor,
		FormatVersion:          enrollment.PeerSnapshotAnchorFormat,
		SignableMetadataHash:   hashHex(signable),
		AdditionalMetadataHash: hashHex(additional),
		ExportEvidenceHash:     hashHex(evidenceBytes),
		ExporterIdentity:       evidence.ExporterIdentity,
		SourceLedgerIdentity:   evidence.SourceLedgerIdentity,
		ExporterPublicKey:      bytes.Clone(export.exporterKey),
	}
	return signJoinAnchor(signer, enrollment.PeerSnapshotAnchorDomain, anchor)
}

func joinAnchorFromVerified(result *VerifiedJoinHistory, signer *mldsa.PrivateKey) (enrollment.JoinAnchor, error) {
	if result == nil || !result.history.Verified() {
		return enrollment.JoinAnchor{}, errors.New("verified Fabric provenance is required before join-anchor issuance")
	}
	verified := result.history
	if signer == nil {
		return enrollment.JoinAnchor{}, errors.New("join-anchor signer does not match the authenticated Pactway policy signer")
	}
	publicKey, ok := signer.Public().(*mldsa.PublicKey)
	if !ok || publicKey.Parameters() != mldsa.MLDSA65() || !verified.MatchesSigner(publicKey) {
		return enrollment.JoinAnchor{}, errors.New("join-anchor signer does not match the authenticated Pactway policy signer")
	}
	identity, ok := verified.JoinIdentity()
	if !ok || identity.BlockNumber == 0 {
		return enrollment.JoinAnchor{}, errors.New("non-genesis verified join target is required")
	}
	anchor := enrollment.JoinAnchor{
		Network: identity.Network, Node: identity.Node, Profile: identity.Profile, Channel: identity.Channel,
		GenesisHash: identity.GenesisHash, BlockNumber: identity.BlockNumber, BlockHash: identity.BlockHash,
		Config: identity.Config,
	}
	encoded, err := json.Marshal(anchor)
	if err != nil {
		return enrollment.JoinAnchor{}, err
	}
	digest := sha256.Sum256(encoded)
	if hex.EncodeToString(digest[:]) != verified.Report().TargetJoinAnchorDigest {
		return enrollment.JoinAnchor{}, errors.New("verified provenance report conflicts with join anchor")
	}
	target := verified.TargetBlock()
	if target == nil || hex.EncodeToString(protoutil.BlockHeaderHash(target.GetHeader())) != anchor.BlockHash {
		return enrollment.JoinAnchor{}, errors.New("verified target block conflicts with join anchor")
	}
	return anchor, nil
}

func signJoinAnchor(signer *mldsa.PrivateKey, domain string, anchor any) ([]byte, error) {
	payload, err := json.Marshal(anchor)
	if err != nil {
		return nil, err
	}
	signature, err := signer.Sign(rand.Reader, append([]byte(domain), payload...), nil)
	if err != nil {
		return nil, err
	}
	return json.Marshal(enrollment.Envelope{Payload: payload, Signature: signature})
}

func hashHex(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}
