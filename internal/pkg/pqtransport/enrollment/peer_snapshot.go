/*
SPDX-License-Identifier: Apache-2.0
*/

package enrollment

import (
	"bytes"
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hyperledger/fabric-lib-go/bccsp"
	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric/common/ledger/snapshot"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport"
	"github.com/hyperledger/fabric/protoutil"
)

// PeerSnapshotAnchorFormat identifies the required peer snapshot approval schema.
const PeerSnapshotAnchorFormat = "fabric-pq/peer-snapshot/v2"

// PeerSnapshotAnchorDomain separates v2 peer snapshot approvals from other
// operator signatures and intentionally has no v1 verification fallback.
const PeerSnapshotAnchorDomain = "fabric-pq/peer-snapshot/v2\x00"

const (
	// SnapshotExportEvidenceFormat identifies the canonical exporter payload.
	SnapshotExportEvidenceFormat = "fabric-pq/snapshot-export/v1"
	// SnapshotExportEvidenceDomain provides domain separation for exporter signatures.
	SnapshotExportEvidenceDomain = "fabric-pq/snapshot-export/v1\x00"
	// SnapshotExportEvidenceFileName is the sidecar carried with native snapshot files.
	SnapshotExportEvidenceFileName = "_pactway_snapshot_export_evidence.json"
)

// PeerSnapshotAnchor approves an exact Fabric state-transfer boundary. The
// supported boundary is a snapshot taken at the signed configuration block.
type PeerSnapshotAnchor struct {
	JoinAnchor
	FormatVersion          string `json:"format_version"`
	SignableMetadataHash   string `json:"signable_metadata_hash"`
	AdditionalMetadataHash string `json:"additional_metadata_hash"`
	ExportEvidenceHash     string `json:"export_evidence_hash"`
	ExporterIdentity       string `json:"exporter_identity"`
	SourceLedgerIdentity   string `json:"source_ledger_identity"`
	ExporterPublicKey      []byte `json:"exporter_public_key"`
}

// SnapshotExportEvidence is the exporter-authenticated binding between a
// native snapshot file set and its verified Fabric configuration boundary.
type SnapshotExportEvidence struct {
	Format                 string            `json:"format"`
	EvidenceID             string            `json:"evidence_id"`
	Network                string            `json:"network"`
	Channel                string            `json:"channel"`
	ExporterIdentity       string            `json:"exporter_identity"`
	SourceLedgerIdentity   string            `json:"source_ledger_identity"`
	GenesisIdentity        string            `json:"genesis_identity"`
	SnapshotBlockNumber    uint64            `json:"snapshot_block_number"`
	SnapshotBlockHash      string            `json:"snapshot_block_hash"`
	ConfigurationSequence  uint64            `json:"configuration_sequence"`
	ConfigurationDigest    string            `json:"configuration_digest"`
	SourceHistoryIdentity  string            `json:"source_history_identity"`
	SignableMetadataHash   string            `json:"signable_metadata_hash"`
	AdditionalMetadataHash string            `json:"additional_metadata_hash"`
	PayloadFiles           map[string]string `json:"payload_files"`
	TransportProfile       string            `json:"transport_profile"`
}

type VerifiedPeerSnapshot struct {
	Channel        string
	Genesis        *cb.Block
	Configuration  *cb.Block
	Files          map[string]string
	ExportEvidence []byte
}

// VerifyPeerSnapshot checks the raw native metadata against the signed anchor.
// The importer must also verify every payload against the authenticated hashes.
func (r *Registry) VerifyPeerSnapshot(signable, additional, exportEvidence []byte, crypto bccsp.BCCSP) (*VerifiedPeerSnapshot, error) {
	var metadata struct {
		Channel     string            `json:"channel_name"`
		BlockNumber uint64            `json:"last_block_number"`
		BlockHash   string            `json:"last_block_hash"`
		Files       map[string]string `json:"snapshot_files_raw_hashes"`
	}
	if err := json.Unmarshal(signable, &metadata); err != nil {
		return nil, fmt.Errorf("decode peer snapshot metadata: %w", err)
	}
	controller := r.Controller(metadata.Channel, crypto)
	if controller == nil {
		return nil, errors.New("managed snapshot channel is not enrolled for protected onboarding")
	}
	var anchor PeerSnapshotAnchor
	if err := r.readJoinAnchor("join-peer", metadata.Channel, PeerSnapshotAnchorDomain, &anchor); err != nil {
		return nil, err
	}
	if anchor.FormatVersion != PeerSnapshotAnchorFormat {
		return nil, errors.New("unsupported peer snapshot anchor format")
	}
	if anchor.SignableMetadataHash != fmt.Sprintf("%x", sha256.Sum256(signable)) ||
		anchor.AdditionalMetadataHash != fmt.Sprintf("%x", sha256.Sum256(additional)) ||
		anchor.ExportEvidenceHash != fmt.Sprintf("%x", sha256.Sum256(exportEvidence)) {
		return nil, errors.New("snapshot metadata conflicts with signed peer join anchor")
	}
	exporterKey, err := mldsa.NewPublicKey(mldsa.MLDSA65(), anchor.ExporterPublicKey)
	if err != nil {
		return nil, fmt.Errorf("parse operator-approved snapshot exporter key: %w", err)
	}
	export, err := VerifySnapshotExportEvidence(exportEvidence, exporterKey)
	if err != nil {
		return nil, err
	}
	genesis, err := controller.GenesisBlock()
	if err != nil {
		return nil, fmt.Errorf("verify genesis for peer snapshot: %w", err)
	}
	raw, err := os.ReadFile(filepath.Join(r.stateDir, joinEvidenceName("join-peer", metadata.Channel)+".block"))
	if err != nil {
		return nil, fmt.Errorf("read peer snapshot configuration block: %w", err)
	}
	block, err := protoutil.UnmarshalBlock(raw)
	if err != nil {
		return nil, err
	}
	expected, err := r.joinAnchor(controller, genesis, block)
	if err != nil {
		return nil, err
	}
	if anchor.JoinAnchor != expected || anchor.BlockNumber != metadata.BlockNumber || anchor.BlockHash != metadata.BlockHash {
		return nil, errors.New("peer snapshot boundary conflicts with signed genesis, configuration or node policy")
	}
	config := anchor.Config
	if export.ExporterIdentity != anchor.ExporterIdentity ||
		export.SourceLedgerIdentity != anchor.SourceLedgerIdentity ||
		export.Network != anchor.Network || export.Channel != anchor.Channel ||
		export.GenesisIdentity != anchor.GenesisHash ||
		export.SnapshotBlockNumber != anchor.BlockNumber || export.SnapshotBlockHash != anchor.BlockHash ||
		export.ConfigurationSequence != config.Sequence || export.ConfigurationDigest != config.Digest ||
		export.TransportProfile != anchor.Profile || export.SignableMetadataHash != anchor.SignableMetadataHash ||
		export.AdditionalMetadataHash != anchor.AdditionalMetadataHash ||
		export.Channel != metadata.Channel || export.SnapshotBlockNumber != metadata.BlockNumber ||
		export.SnapshotBlockHash != metadata.BlockHash || !sameSnapshotHashes(export.PayloadFiles, metadata.Files) {
		return nil, errors.New("authenticated snapshot export evidence conflicts with operator-approved boundary")
	}
	if err := verifySnapshotAdditionalMetadata(signable, additional); err != nil {
		return nil, err
	}
	return &VerifiedPeerSnapshot{
		Channel: metadata.Channel, Genesis: genesis, Configuration: block, Files: metadata.Files,
		ExportEvidence: append([]byte(nil), exportEvidence...),
	}, nil
}

// StorePeerSnapshotExportEvidence durably retains the exporter evidence that
// the signed peer anchor requires during restart recovery.
func (r *Registry) StorePeerSnapshotExportEvidence(channel string, evidence []byte) error {
	if !r.RequiresProtection(channel) {
		return errors.New("snapshot export evidence requires an enrolled protected channel")
	}
	var anchor PeerSnapshotAnchor
	if err := r.readJoinAnchor("join-peer", channel, PeerSnapshotAnchorDomain, &anchor); err != nil {
		return err
	}
	if anchor.ExportEvidenceHash != fmt.Sprintf("%x", sha256.Sum256(evidence)) {
		return errors.New("snapshot export evidence conflicts with signed peer join anchor")
	}
	key, err := mldsa.NewPublicKey(mldsa.MLDSA65(), anchor.ExporterPublicKey)
	if err != nil {
		return fmt.Errorf("parse operator-approved snapshot exporter key: %w", err)
	}
	export, err := VerifySnapshotExportEvidence(evidence, key)
	if err != nil {
		return err
	}
	if export.ExporterIdentity != anchor.ExporterIdentity || export.SourceLedgerIdentity != anchor.SourceLedgerIdentity {
		return errors.New("snapshot export evidence conflicts with signed exporter identity")
	}
	name := filepath.Join(r.stateDir, joinEvidenceName("join-peer", channel)+".export")
	existing, err := os.ReadFile(name)
	if err == nil {
		if !bytes.Equal(existing, evidence) {
			return errors.New("stored snapshot export evidence conflicts with authenticated evidence")
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temp, err := os.CreateTemp(r.stateDir, ".snapshot-export-")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.Write(evidence); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Link(tempName, name); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return err
		}
		existing, readErr := os.ReadFile(name)
		if readErr != nil {
			return readErr
		}
		if !bytes.Equal(existing, evidence) {
			return errors.New("stored snapshot export evidence conflicts with authenticated evidence")
		}
	}
	dir, err := os.Open(r.stateDir)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

// LoadPeerSnapshotExportEvidence retrieves the durable exporter proof needed
// to reopen a protected peer snapshot after restart.
func (r *Registry) LoadPeerSnapshotExportEvidence(channel string) ([]byte, error) {
	if !r.RequiresProtection(channel) {
		return nil, errors.New("snapshot export evidence requires an enrolled protected channel")
	}
	return os.ReadFile(filepath.Join(r.stateDir, joinEvidenceName("join-peer", channel)+".export"))
}

// VerifySnapshotExportEvidence authenticates the canonical evidence payload
// with the independently approved exporter key.
func VerifySnapshotExportEvidence(encoded []byte, key *mldsa.PublicKey) (SnapshotExportEvidence, error) {
	var evidence SnapshotExportEvidence
	if _, err := verify(encoded, key, SnapshotExportEvidenceDomain, &evidence); err != nil {
		return SnapshotExportEvidence{}, fmt.Errorf("verify authenticated snapshot export evidence: %w", err)
	}
	if evidence.Format != SnapshotExportEvidenceFormat || !isSnapshotHash(evidence.EvidenceID) ||
		evidence.Network == "" || evidence.Channel == "" ||
		evidence.ExporterIdentity == "" || evidence.SourceLedgerIdentity == "" ||
		evidence.SnapshotBlockNumber == 0 || evidence.ConfigurationSequence == 0 ||
		evidence.TransportProfile != pqtransport.ProfileV1 || len(evidence.PayloadFiles) == 0 {
		return SnapshotExportEvidence{}, errors.New("snapshot export evidence is incomplete or uses an unsupported format")
	}
	for _, digest := range []string{
		evidence.GenesisIdentity, evidence.SnapshotBlockHash, evidence.ConfigurationDigest,
		evidence.SourceHistoryIdentity, evidence.SignableMetadataHash, evidence.AdditionalMetadataHash,
	} {
		if !isSnapshotHash(digest) {
			return SnapshotExportEvidence{}, errors.New("snapshot export evidence contains an invalid digest")
		}
	}
	for name, digest := range evidence.PayloadFiles {
		if !filepath.IsLocal(name) || filepath.Base(name) != name || name == "." || name == ".." ||
			name == snapshot.SignableMetadataFileName ||
			name == snapshot.AdditionalMetadataFileName ||
			name == SnapshotExportEvidenceFileName ||
			strings.ContainsAny(name, `/\`) || len(name) == 0 ||
			len(digest) != sha256.Size*2 || !isSnapshotHash(digest) {
			return SnapshotExportEvidence{}, fmt.Errorf("snapshot export evidence contains an invalid payload entry %q", name)
		}
	}
	return evidence, nil
}

func verifySnapshotAdditionalMetadata(signable, additional []byte) error {
	var metadata struct {
		SnapshotHash string `json:"snapshot_hash"`
	}
	if err := json.Unmarshal(additional, &metadata); err != nil {
		return fmt.Errorf("decode native additional snapshot metadata: %w", err)
	}
	if metadata.SnapshotHash != fmt.Sprintf("%x", sha256.Sum256(signable)) {
		return errors.New("native additional metadata conflicts with exact signable metadata bytes")
	}
	return nil
}

func sameSnapshotHashes(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for name, digest := range left {
		if right[name] != digest {
			return false
		}
	}
	return true
}

func isSnapshotHash(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == sha256.Size && hex.EncodeToString(raw) == value
}
