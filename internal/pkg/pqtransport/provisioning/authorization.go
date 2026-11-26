/*
SPDX-License-Identifier: Apache-2.0
*/

package provisioning

import (
	"bytes"
	"crypto/mldsa"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hyperledger/fabric/internal/pkg/pqtransport"
)

const (
	// ExporterAuthorizationFormat identifies the signed pre-export trust record.
	ExporterAuthorizationFormat = "fabric-pq/exporter-authorization/v1"
	exporterAuthorizationDomain = ExporterAuthorizationFormat + "\x00"
)

// ExporterAuthorization binds exporter trust, source-ledger selection, and
// the approved snapshot boundary before an export package is created.
type ExporterAuthorization struct {
	Format                string `json:"format"`
	AuthorityIdentity     string `json:"authority_identity"`
	ApprovalIdentity      string `json:"approval_identity"`
	Generation            uint64 `json:"generation"`
	Network               string `json:"network"`
	Channel               string `json:"channel"`
	ExporterIdentity      string `json:"exporter_identity"`
	ExporterPublicKey     []byte `json:"exporter_public_key"`
	SourceLedgerIdentity  string `json:"source_ledger_identity"`
	SourceLedgerPath      string `json:"source_ledger_path"`
	TrustedGenesis        string `json:"trusted_genesis"`
	ConfigurationSequence uint64 `json:"configuration_sequence"`
	ConfigurationDigest   string `json:"configuration_digest"`
	SnapshotBlockNumber   uint64 `json:"snapshot_block_number"`
	SnapshotBlockHash     string `json:"snapshot_block_hash"`
	SourceHistoryIdentity string `json:"source_history_identity"`
	TransportProfile      string `json:"transport_profile"`
}

// VerifiedExporterAuthorization can only be obtained by verifying an
// authorization with an independently pinned authority identity and key.
type VerifiedExporterAuthorization struct {
	authorization ExporterAuthorization
	exporterKey   *mldsa.PublicKey
}

// SignExporterAuthorization signs the pre-export authorization with the
// provisioning authority's key, not the exporter or peer policy key.
func SignExporterAuthorization(authorization ExporterAuthorization, signer *mldsa.PrivateKey) ([]byte, error) {
	if !isMLDSA65Signer(signer) {
		return nil, errors.New("provisioning authority must use an ML-DSA-65 signing key")
	}
	authorization.Format = ExporterAuthorizationFormat
	if authorization.ApprovalIdentity == "" {
		identity := make([]byte, 32)
		if _, err := rand.Read(identity); err != nil {
			return nil, fmt.Errorf("generate provisioning approval identity: %w", err)
		}
		authorization.ApprovalIdentity = hex.EncodeToString(identity)
	}
	if err := validateExporterAuthorization(authorization); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(authorization)
	if err != nil {
		return nil, fmt.Errorf("encode exporter authorization: %w", err)
	}
	signature, err := signer.Sign(rand.Reader, append([]byte(exporterAuthorizationDomain), payload...), nil)
	if err != nil {
		return nil, fmt.Errorf("sign exporter authorization: %w", err)
	}
	return json.Marshal(struct {
		Payload   []byte `json:"payload"`
		Signature []byte `json:"signature"`
	}{Payload: payload, Signature: signature})
}

// VerifyExporterAuthorization authenticates an authorization against the
// authority identity and key installed independently by the provisioner.
func VerifyExporterAuthorization(
	encoded []byte,
	expectedAuthority string,
	authorityKey *mldsa.PublicKey,
) (*VerifiedExporterAuthorization, error) {
	if expectedAuthority == "" || expectedAuthority != strings.TrimSpace(expectedAuthority) ||
		authorityKey == nil || authorityKey.Parameters() != mldsa.MLDSA65() {
		return nil, errors.New("independent provisioning authority identity and ML-DSA-65 key are required")
	}
	var envelope struct {
		Payload   []byte `json:"payload"`
		Signature []byte `json:"signature"`
	}
	if err := json.Unmarshal(encoded, &envelope); err != nil {
		return nil, fmt.Errorf("decode exporter authorization envelope: %w", err)
	}
	if len(envelope.Payload) == 0 || len(envelope.Signature) == 0 {
		return nil, errors.New("exporter authorization signature is invalid")
	}
	if err := mldsa.Verify(
		authorityKey,
		append([]byte(exporterAuthorizationDomain), envelope.Payload...),
		envelope.Signature,
		nil,
	); err != nil {
		return nil, errors.New("exporter authorization signature is invalid")
	}
	var authorization ExporterAuthorization
	if err := json.Unmarshal(envelope.Payload, &authorization); err != nil {
		return nil, fmt.Errorf("decode exporter authorization payload: %w", err)
	}
	if err := validateExporterAuthorization(authorization); err != nil {
		return nil, err
	}
	if authorization.AuthorityIdentity != expectedAuthority {
		return nil, errors.New("exporter authorization was not issued by the independently trusted authority")
	}
	exporterKey, err := mldsa.NewPublicKey(mldsa.MLDSA65(), authorization.ExporterPublicKey)
	if err != nil {
		return nil, fmt.Errorf("parse authorized exporter key: %w", err)
	}
	return &VerifiedExporterAuthorization{authorization: authorization, exporterKey: exporterKey}, nil
}

// SnapshotExporterTrust returns the existing snapshot verifier's trust pin
// only from an independently verified authorization.
func (v *VerifiedExporterAuthorization) SnapshotExporterTrust(history *VerifiedJoinHistory) (*SnapshotExporterTrust, error) {
	if v == nil || v.exporterKey == nil {
		return nil, errors.New("verified exporter authorization is required")
	}
	if history == nil || history.history == nil || !history.history.Verified() {
		return nil, errors.New("registry-bound verified Fabric history is required")
	}
	identity, ok := history.history.JoinIdentity()
	if !ok {
		return nil, errors.New("verified Fabric join identity is unavailable")
	}
	report := history.Report()
	authorization := v.authorization
	if authorization.Network != identity.Network || authorization.Channel != identity.Channel ||
		authorization.TrustedGenesis != report.TrustedGenesisBlockIdentity ||
		authorization.SnapshotBlockNumber != report.TargetBlockNumber ||
		authorization.SnapshotBlockHash != report.TargetBlockHash ||
		authorization.ConfigurationSequence != report.TargetConfigurationSequence ||
		authorization.ConfigurationDigest != report.TargetConfigurationDigest ||
		authorization.SourceHistoryIdentity != report.SourceHistoryIdentity ||
		authorization.TransportProfile != identity.Profile {
		return nil, errors.New("exporter authorization conflicts with registry-bound Fabric history")
	}
	return NewSnapshotExporterTrust(
		authorization.ExporterIdentity,
		authorization.SourceLedgerIdentity,
		v.exporterKey,
	)
}

// Authorization returns a defensive copy of the authenticated claims.
func (v *VerifiedExporterAuthorization) Authorization() ExporterAuthorization {
	if v == nil {
		return ExporterAuthorization{}
	}
	authorization := v.authorization
	authorization.ExporterPublicKey = bytes.Clone(v.authorization.ExporterPublicKey)
	return authorization
}

func validateExporterAuthorization(authorization ExporterAuthorization) error {
	if authorization.Format != ExporterAuthorizationFormat ||
		!validAuthorizationText(authorization.AuthorityIdentity) ||
		!isLocalHash(authorization.ApprovalIdentity) ||
		authorization.Generation == 0 ||
		!validAuthorizationText(authorization.Network) ||
		!validAuthorizationText(authorization.Channel) ||
		!validAuthorizationText(authorization.ExporterIdentity) ||
		len(authorization.ExporterPublicKey) == 0 ||
		!validAuthorizationText(authorization.SourceLedgerIdentity) ||
		!filepath.IsAbs(authorization.SourceLedgerPath) ||
		filepath.Clean(authorization.SourceLedgerPath) != authorization.SourceLedgerPath ||
		authorization.SourceLedgerPath == filepath.VolumeName(authorization.SourceLedgerPath)+string(filepath.Separator) ||
		!isLocalHash(authorization.TrustedGenesis) ||
		authorization.ConfigurationSequence == 0 ||
		!isLocalHash(authorization.ConfigurationDigest) ||
		authorization.SnapshotBlockNumber == 0 ||
		!isLocalHash(authorization.SnapshotBlockHash) ||
		!isLocalHash(authorization.SourceHistoryIdentity) ||
		authorization.TransportProfile != pqtransport.ProfileV1 {
		return errors.New("exporter authorization is incomplete or unsupported")
	}
	if _, err := mldsa.NewPublicKey(mldsa.MLDSA65(), authorization.ExporterPublicKey); err != nil {
		return fmt.Errorf("invalid authorized exporter public key: %w", err)
	}
	return nil
}

func validAuthorizationText(value string) bool {
	return value != "" && value == strings.TrimSpace(value) && !strings.ContainsRune(value, '\x00')
}

// VerifyAuthorizedSourcePath ensures the configured path exists and resolves
// to the same canonical directory that the provisioner authorized.
func (v *VerifiedExporterAuthorization) VerifyAuthorizedSourcePath() error {
	if v == nil {
		return errors.New("verified exporter authorization is required")
	}
	info, err := os.Stat(v.authorization.SourceLedgerPath)
	if err != nil {
		return fmt.Errorf("stat authorized source ledger: %w", err)
	}
	if !info.IsDir() {
		return errors.New("authorized source ledger path is not a directory")
	}
	resolved, err := filepath.EvalSymlinks(v.authorization.SourceLedgerPath)
	if err != nil {
		return fmt.Errorf("resolve authorized source ledger path: %w", err)
	}
	if resolved != v.authorization.SourceLedgerPath {
		return errors.New("authorized source ledger path resolves through a symlink")
	}
	return nil
}
