/*
SPDX-License-Identifier: Apache-2.0
*/

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
	"io"
	"maps"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/hyperledger/fabric/core/ledger/kvledger"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/enrollment"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/provenance"
)

// SnapshotExportEvidenceFileName is the sidecar carried with native snapshots.
const SnapshotExportEvidenceFileName = enrollment.SnapshotExportEvidenceFileName

// SnapshotExportClaims are the exporter-signed claims for a native snapshot.
type SnapshotExportClaims = enrollment.SnapshotExportEvidence

// SnapshotExporterTrust is supplied by the independently controlled
// provisioning authority, never loaded from snapshot metadata or evidence.
type SnapshotExporterTrust struct {
	identity     string
	sourceLedger string
	publicKey    *mldsa.PublicKey
}

func isMLDSA65Signer(signer *mldsa.PrivateKey) bool {
	if signer == nil {
		return false
	}
	publicKey, ok := signer.Public().(*mldsa.PublicKey)
	return ok && publicKey.Parameters() == mldsa.MLDSA65()
}

// NewSnapshotExporterTrust constructs a pin from provisioner-controlled
// identity, ledger and public-key configuration.
func NewSnapshotExporterTrust(identity, sourceLedger string, publicKey *mldsa.PublicKey) (*SnapshotExporterTrust, error) {
	if strings.TrimSpace(identity) == "" || strings.TrimSpace(sourceLedger) == "" ||
		identity != strings.TrimSpace(identity) || sourceLedger != strings.TrimSpace(sourceLedger) ||
		publicKey == nil || publicKey.Parameters() != mldsa.MLDSA65() {
		return nil, errors.New("trusted exporter identity, source ledger and ML-DSA-65 key are required")
	}
	return &SnapshotExporterTrust{identity: identity, sourceLedger: sourceLedger, publicKey: publicKey}, nil
}

type snapshotMetadata struct {
	Channel     string            `json:"channel_name"`
	BlockNumber uint64            `json:"last_block_number"`
	BlockHash   string            `json:"last_block_hash"`
	Files       map[string]string `json:"snapshot_files_raw_hashes"`
}

// VerifiedSnapshotExport is an opaque, privately staged snapshot whose exact
// contents have passed exporter authentication and boundary verification.
// Call Close when the staged snapshot is no longer needed.
type VerifiedSnapshotExport struct {
	history       *VerifiedJoinHistory
	trust         *SnapshotExporterTrust
	stageDir      string
	evidenceBytes []byte
	signable      []byte
	additional    []byte
	exporterKey   []byte
}

// Directory returns the private staged directory that must be distributed or
// imported; using the original source directory would reintroduce TOCTOU risk.
func (v *VerifiedSnapshotExport) Directory() string {
	if v == nil {
		return ""
	}
	return v.stageDir
}

// Close removes the private staged snapshot.
func (v *VerifiedSnapshotExport) Close() error {
	if v == nil || v.stageDir == "" {
		return nil
	}
	if err := os.Chmod(v.stageDir, 0o700); err != nil {
		return err
	}
	err := os.RemoveAll(v.stageDir)
	if err == nil {
		v.stageDir = ""
	}
	return err
}

// SignSnapshotExportEvidence creates exporter-authenticated evidence for a
// native Fabric snapshot. The exporter process must call this only after
// exporting the claimed channel and boundary from its approved source ledger.
func SignSnapshotExportEvidence(snapshotDir string, claims SnapshotExportClaims, signer *mldsa.PrivateKey) ([]byte, error) {
	if !isMLDSA65Signer(signer) {
		return nil, errors.New("snapshot exporter must use an ML-DSA-65 signing key")
	}
	root, err := os.OpenRoot(snapshotDir)
	if err != nil {
		return nil, fmt.Errorf("open snapshot export: %w", err)
	}
	defer root.Close()
	signable, err := root.ReadFile(kvledger.SnapshotSignableMetadataFileName)
	if err != nil {
		return nil, fmt.Errorf("read native signable metadata: %w", err)
	}
	additional, err := root.ReadFile(kvledger.SnapshotAdditionalMetadataFileName)
	if err != nil {
		return nil, fmt.Errorf("read native additional metadata: %w", err)
	}
	metadata, err := decodeSnapshotMetadata(signable)
	if err != nil {
		return nil, err
	}
	if claims.Channel != metadata.Channel || claims.SnapshotBlockNumber != metadata.BlockNumber ||
		claims.SnapshotBlockHash != metadata.BlockHash {
		return nil, errors.New("export claims conflict with native snapshot metadata")
	}
	if err := verifyNativeAdditionalMetadata(signable, additional); err != nil {
		return nil, err
	}
	claims.Format = enrollment.SnapshotExportEvidenceFormat
	evidenceID := make([]byte, sha256.Size)
	if _, err := rand.Read(evidenceID); err != nil {
		return nil, fmt.Errorf("generate snapshot export evidence identity: %w", err)
	}
	claims.EvidenceID = hex.EncodeToString(evidenceID)
	claims.SignableMetadataHash = hashHex(signable)
	claims.AdditionalMetadataHash = hashHex(additional)
	claims.PayloadFiles = cloneHashes(metadata.Files)
	if err := validateSnapshotClaims(claims); err != nil {
		return nil, err
	}
	if err := verifySnapshotDirectory(root, metadata.Files, ""); err != nil {
		return nil, err
	}
	for name, digest := range metadata.Files {
		if err := verifySnapshotFile(root, name, digest); err != nil {
			return nil, err
		}
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}
	signature, err := signer.Sign(rand.Reader, append([]byte(enrollment.SnapshotExportEvidenceDomain), payload...), nil)
	if err != nil {
		return nil, err
	}
	return json.Marshal(enrollment.Envelope{Payload: payload, Signature: signature})
}

// VerifySnapshotExport authenticates the exporter and copies the exact
// snapshot bytes into a private directory before returning a signable token.
func VerifySnapshotExport(
	verified *VerifiedJoinHistory,
	snapshotDir string,
	trust *SnapshotExporterTrust,
) (*VerifiedSnapshotExport, error) {
	if verified == nil || verified.history == nil || !verified.history.Verified() {
		return nil, errors.New("verified Fabric provenance is required before snapshot export approval")
	}
	identity, ok := verified.history.JoinIdentity()
	if !ok {
		return nil, errors.New("verified Fabric join identity is unavailable")
	}
	joinAnchor := enrollment.JoinAnchor{
		Network: identity.Network, Node: identity.Node, Profile: identity.Profile, Channel: identity.Channel,
		GenesisHash: identity.GenesisHash, BlockNumber: identity.BlockNumber, BlockHash: identity.BlockHash,
		Config: identity.Config,
	}
	if trust == nil || trust.publicKey == nil {
		return nil, errors.New("independently trusted snapshot exporter is required")
	}
	source, err := os.OpenRoot(snapshotDir)
	if err != nil {
		return nil, fmt.Errorf("open snapshot source: %w", err)
	}
	defer source.Close()
	signable, err := source.ReadFile(kvledger.SnapshotSignableMetadataFileName)
	if err != nil {
		return nil, fmt.Errorf("read native signable metadata: %w", err)
	}
	additional, err := source.ReadFile(kvledger.SnapshotAdditionalMetadataFileName)
	if err != nil {
		return nil, fmt.Errorf("read native additional metadata: %w", err)
	}
	evidenceBytes, err := source.ReadFile(SnapshotExportEvidenceFileName)
	if err != nil {
		return nil, fmt.Errorf("read authenticated snapshot export evidence: %w", err)
	}
	evidence, err := verifySnapshotExportEvidence(evidenceBytes, trust.publicKey)
	if err != nil {
		return nil, err
	}
	metadata, err := decodeSnapshotMetadata(signable)
	if err != nil {
		return nil, err
	}
	if err := validateSnapshotExportBoundary(evidence, trust, joinAnchor, verified.Report(), metadata, signable, additional); err != nil {
		return nil, err
	}
	if err := verifyNativeAdditionalMetadata(signable, additional); err != nil {
		return nil, err
	}
	if err := verifySnapshotDirectory(source, evidence.PayloadFiles, SnapshotExportEvidenceFileName); err != nil {
		return nil, err
	}
	stage, err := os.MkdirTemp("", "fabric-pq-approved-snapshot-")
	if err != nil {
		return nil, fmt.Errorf("create private snapshot staging directory: %w", err)
	}
	result := &VerifiedSnapshotExport{
		history: verified, trust: trust, stageDir: stage, evidenceBytes: bytes.Clone(evidenceBytes),
		signable: bytes.Clone(signable), additional: bytes.Clone(additional),
		exporterKey: bytes.Clone(trust.publicKey.Bytes()),
	}
	staged := false
	defer func() {
		if !staged {
			_ = result.Close()
		}
	}()
	names := make([]string, 0, len(evidence.PayloadFiles))
	for name := range evidence.PayloadFiles {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := copyVerifiedSnapshotFile(source, stage, name, evidence.PayloadFiles[name]); err != nil {
			return nil, err
		}
	}
	if err := writeStagedSnapshotFile(stage, kvledger.SnapshotSignableMetadataFileName, signable); err != nil {
		return nil, err
	}
	if err := writeStagedSnapshotFile(stage, kvledger.SnapshotAdditionalMetadataFileName, additional); err != nil {
		return nil, err
	}
	if err := writeStagedSnapshotFile(stage, SnapshotExportEvidenceFileName, evidenceBytes); err != nil {
		return nil, err
	}
	for _, name := range append(names, kvledger.SnapshotSignableMetadataFileName, kvledger.SnapshotAdditionalMetadataFileName, SnapshotExportEvidenceFileName) {
		if err := os.Chmod(filepath.Join(stage, name), 0o400); err != nil {
			return nil, err
		}
	}
	if err := os.Chmod(stage, 0o500); err != nil {
		return nil, err
	}
	staged = true
	return result, nil
}

func verifySnapshotExportEvidence(encoded []byte, key *mldsa.PublicKey) (SnapshotExportClaims, error) {
	return enrollment.VerifySnapshotExportEvidence(encoded, key)
}

func validateSnapshotExportBoundary(
	evidence SnapshotExportClaims,
	trust *SnapshotExporterTrust,
	anchor enrollment.JoinAnchor,
	report provenance.Report,
	metadata snapshotMetadata,
	signable, additional []byte,
) error {
	if evidence.ExporterIdentity != trust.identity || evidence.SourceLedgerIdentity != trust.sourceLedger {
		return errors.New("snapshot exporter or source ledger is not independently approved")
	}
	if evidence.Network != anchor.Network || evidence.Channel != anchor.Channel ||
		evidence.GenesisIdentity != anchor.GenesisHash || evidence.SnapshotBlockNumber != anchor.BlockNumber ||
		evidence.SnapshotBlockHash != anchor.BlockHash || evidence.ConfigurationSequence != anchor.Config.Sequence ||
		evidence.ConfigurationDigest != anchor.Config.Digest || evidence.SourceHistoryIdentity != report.SourceHistoryIdentity ||
		evidence.TransportProfile != anchor.Profile {
		return errors.New("authenticated export evidence conflicts with registry-bound Fabric history")
	}
	if metadata.Channel != anchor.Channel || metadata.BlockNumber != anchor.BlockNumber ||
		metadata.BlockHash != anchor.BlockHash || !equalHashes(metadata.Files, evidence.PayloadFiles) ||
		evidence.SignableMetadataHash != hashHex(signable) || evidence.AdditionalMetadataHash != hashHex(additional) {
		return errors.New("authenticated export evidence conflicts with native snapshot bytes")
	}
	return nil
}

func decodeSnapshotMetadata(encoded []byte) (snapshotMetadata, error) {
	var metadata snapshotMetadata
	if err := json.Unmarshal(encoded, &metadata); err != nil {
		return snapshotMetadata{}, fmt.Errorf("decode native snapshot metadata: %w", err)
	}
	if metadata.Channel == "" || metadata.BlockHash == "" || len(metadata.Files) == 0 {
		return snapshotMetadata{}, errors.New("native snapshot metadata is incomplete")
	}
	for name, digest := range metadata.Files {
		if err := validateSnapshotFileName(name); err != nil {
			return snapshotMetadata{}, err
		}
		if err := validateHash(digest); err != nil {
			return snapshotMetadata{}, fmt.Errorf("invalid native snapshot digest for %q: %w", name, err)
		}
	}
	return metadata, nil
}

func validateSnapshotClaims(claims SnapshotExportClaims) error {
	if claims.Format != enrollment.SnapshotExportEvidenceFormat ||
		!isLocalHash(claims.EvidenceID) || claims.Network == "" || claims.Channel == "" || claims.ExporterIdentity == "" ||
		claims.SourceLedgerIdentity == "" || claims.GenesisIdentity == "" ||
		claims.SnapshotBlockNumber == 0 || claims.ConfigurationSequence == 0 ||
		claims.TransportProfile != pqtransport.ProfileV1 || len(claims.PayloadFiles) == 0 ||
		claims.SignableMetadataHash == "" || claims.AdditionalMetadataHash == "" {
		return errors.New("snapshot export claims are incomplete or use an unsupported profile")
	}
	for _, digest := range []string{
		claims.GenesisIdentity, claims.SnapshotBlockHash, claims.ConfigurationDigest,
		claims.SourceHistoryIdentity, claims.SignableMetadataHash, claims.AdditionalMetadataHash,
	} {
		if digest != "" {
			if err := validateHash(digest); err != nil {
				return err
			}
		}
	}
	for name, digest := range claims.PayloadFiles {
		if err := validateSnapshotFileName(name); err != nil {
			return err
		}
		if err := validateHash(digest); err != nil {
			return fmt.Errorf("invalid snapshot payload digest for %q: %w", name, err)
		}
	}
	return nil
}

func verifyNativeAdditionalMetadata(signable, additional []byte) error {
	var metadata struct {
		SnapshotHash string `json:"snapshot_hash"`
	}
	if err := json.Unmarshal(additional, &metadata); err != nil {
		return fmt.Errorf("decode native additional snapshot metadata: %w", err)
	}
	if metadata.SnapshotHash != hashHex(signable) {
		return errors.New("native additional metadata does not hash the exact signable metadata bytes")
	}
	return nil
}

func verifySnapshotDirectory(root *os.Root, files map[string]string, evidenceName string) error {
	expected := map[string]struct{}{
		kvledger.SnapshotSignableMetadataFileName:   {},
		kvledger.SnapshotAdditionalMetadataFileName: {},
	}
	if evidenceName != "" {
		expected[evidenceName] = struct{}{}
	}
	for name := range files {
		if err := validateSnapshotFileName(name); err != nil {
			return err
		}
		expected[name] = struct{}{}
	}
	listing, err := root.Open(".")
	if err != nil {
		return fmt.Errorf("open snapshot directory inventory: %w", err)
	}
	defer listing.Close()
	entries, err := listing.ReadDir(-1)
	if err != nil {
		return fmt.Errorf("list snapshot files: %w", err)
	}
	if len(entries) != len(expected) {
		return errors.New("snapshot directory contains missing or unexpected files")
	}
	for _, entry := range entries {
		if _, ok := expected[entry.Name()]; !ok || !entry.Type().IsRegular() {
			return fmt.Errorf("snapshot directory contains unexpected or non-regular entry %q", entry.Name())
		}
		info, err := root.Lstat(entry.Name())
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("snapshot entry %q is not a regular file", entry.Name())
		}
	}
	return nil
}

func verifySnapshotFile(root *os.Root, name, expected string) error {
	file, err := root.Open(name)
	if err != nil {
		return err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return err
	}
	if hex.EncodeToString(hash.Sum(nil)) != expected {
		return fmt.Errorf("snapshot payload %q conflicts with authenticated digest", name)
	}
	return nil
}

func copyVerifiedSnapshotFile(source *os.Root, stage, name, expected string) error {
	before, err := source.Lstat(name)
	if err != nil {
		return err
	}
	if !before.Mode().IsRegular() {
		return fmt.Errorf("snapshot payload %q is not a regular file", name)
	}
	input, err := source.Open(name)
	if err != nil {
		return err
	}
	defer input.Close()
	opened, err := input.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(before, opened) {
		return fmt.Errorf("snapshot payload %q changed while being opened", name)
	}
	output, err := os.OpenFile(filepath.Join(stage, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	hash := sha256.New()
	_, copyErr := io.Copy(io.MultiWriter(output, hash), input)
	closeErr := output.Close()
	if err := errors.Join(copyErr, closeErr); err != nil {
		return err
	}
	if hex.EncodeToString(hash.Sum(nil)) != expected {
		return fmt.Errorf("snapshot payload %q changed or conflicts with authenticated evidence", name)
	}
	return nil
}

func writeStagedSnapshotFile(stage, name string, value []byte) error {
	return os.WriteFile(filepath.Join(stage, name), value, 0o600)
}

func validateSnapshotFileName(name string) error {
	if name == "" || !filepath.IsLocal(name) || filepath.Base(name) != name ||
		strings.ContainsAny(name, `/\`) || name == "." || name == ".." ||
		name == kvledger.SnapshotSignableMetadataFileName ||
		name == kvledger.SnapshotAdditionalMetadataFileName ||
		name == SnapshotExportEvidenceFileName {
		return fmt.Errorf("invalid or reserved snapshot payload filename %q", name)
	}
	return nil
}

func validateHash(value string) error {
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != sha256.Size || hex.EncodeToString(raw) != value {
		return errors.New("expected lowercase SHA-256 hex")
	}
	return nil
}

func isLocalHash(value string) bool {
	return validateHash(value) == nil
}

func equalHashes(left, right map[string]string) bool {
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

func cloneHashes(source map[string]string) map[string]string {
	result := make(map[string]string, len(source))
	maps.Copy(result, source)
	return result
}
