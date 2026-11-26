/*
SPDX-License-Identifier: Apache-2.0
*/

// Package exportauth authenticates provisioning authorization and execution records.
package exportauth

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
	"os"
	"path/filepath"
	"strings"

	"github.com/hyperledger/fabric/internal/pkg/pqtransport"
)

const (
	AuthorizationFormat = "fabric-pq/exporter-authorization/v1"
	authorizationDomain = AuthorizationFormat + "\x00"
	ExecutionFormat     = "fabric-pq/exporter-execution/v1"
	executionDomain     = ExecutionFormat + "\x00"
)

type Authorization struct {
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
	ExecutablePath        string `json:"executable_path"`
	ExecutableSHA256      string `json:"executable_sha256"`
	TrustedGenesis        string `json:"trusted_genesis"`
	ConfigurationSequence uint64 `json:"configuration_sequence"`
	ConfigurationDigest   string `json:"configuration_digest"`
	SnapshotBlockNumber   uint64 `json:"snapshot_block_number"`
	SnapshotBlockHash     string `json:"snapshot_block_hash"`
	SourceHistoryIdentity string `json:"source_history_identity"`
	TransportProfile      string `json:"transport_profile"`
}

// Execution is the authority's observation of the controlled exporter, not
// an independent measurement of the ledger opened by that exporter.
type Execution struct {
	Format               string   `json:"format"`
	AuthorizationDigest  string   `json:"authorization_digest"`
	ApprovalIdentity     string   `json:"approval_identity"`
	Generation           uint64   `json:"generation"`
	SourceLedgerIdentity string   `json:"source_ledger_identity"`
	SourceLedgerPath     string   `json:"source_ledger_path"`
	Channel              string   `json:"channel"`
	SnapshotBlockNumber  uint64   `json:"snapshot_block_number"`
	SnapshotBlockHash    string   `json:"snapshot_block_hash"`
	ExecutablePath       string   `json:"executable_path"`
	ExecutableSHA256     string   `json:"executable_sha256"`
	ExportEvidenceDigest string   `json:"export_evidence_digest"`
	Launcher             []string `json:"launcher"`
	Invocation           []string `json:"invocation"`
	Result               string   `json:"result"`
}

type envelope struct {
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

type VerifiedAuthorization struct {
	claims       Authorization
	authorityKey *mldsa.PublicKey
	encoded      []byte
}

type VerifiedExecution struct {
	authorizationDigest string
	evidenceDigest      string
	encoded             []byte
}

func SignAuthorization(claims Authorization, signer *mldsa.PrivateKey) ([]byte, error) {
	if !validSigner(signer) {
		return nil, errors.New("provisioning authority must use an ML-DSA-65 signing key")
	}
	claims.Format = AuthorizationFormat
	if claims.ApprovalIdentity == "" {
		identity := make([]byte, sha256.Size)
		if _, err := rand.Read(identity); err != nil {
			return nil, fmt.Errorf("generate provisioning approval identity: %w", err)
		}
		claims.ApprovalIdentity = hex.EncodeToString(identity)
	}
	if err := validateAuthorization(claims); err != nil {
		return nil, err
	}
	if bytes.Equal(claims.ExporterPublicKey, signer.Public().(*mldsa.PublicKey).Bytes()) {
		return nil, errors.New("exporter key must be independent of provisioning authority")
	}
	return sign(authorizationDomain, claims, signer)
}

func VerifyAuthorization(encoded []byte, expectedAuthority string, key *mldsa.PublicKey) (*VerifiedAuthorization, error) {
	if !validText(expectedAuthority) || key == nil || key.Parameters() != mldsa.MLDSA65() {
		return nil, errors.New("independent provisioning authority identity and ML-DSA-65 key are required")
	}
	var claims Authorization
	if err := verify(authorizationDomain, encoded, key, &claims); err != nil {
		return nil, fmt.Errorf("verify exporter authorization: %w", err)
	}
	if err := validateAuthorization(claims); err != nil {
		return nil, err
	}
	if claims.AuthorityIdentity != expectedAuthority {
		return nil, errors.New("exporter authorization was not issued by the independently trusted authority")
	}
	if bytes.Equal(claims.ExporterPublicKey, key.Bytes()) {
		return nil, errors.New("exporter key must be independent of provisioning authority")
	}
	authorityCopy, err := mldsa.NewPublicKey(mldsa.MLDSA65(), key.Bytes())
	if err != nil {
		return nil, fmt.Errorf("copy verified provisioning authority: %w", err)
	}
	return &VerifiedAuthorization{claims: claims, authorityKey: authorityCopy, encoded: bytes.Clone(encoded)}, nil
}

func (v *VerifiedAuthorization) Claims() Authorization {
	if v == nil {
		return Authorization{}
	}
	claims := v.claims
	claims.ExporterPublicKey = bytes.Clone(claims.ExporterPublicKey)
	return claims
}

func (v *VerifiedAuthorization) Encoded() []byte {
	if v == nil {
		return nil
	}
	return bytes.Clone(v.encoded)
}

func (v *VerifiedAuthorization) MatchesAuthority(identity string, key *mldsa.PublicKey) bool {
	return v != nil && v.authorityKey != nil && key != nil &&
		v.claims.AuthorityIdentity == identity && bytes.Equal(v.authorityKey.Bytes(), key.Bytes())
}

func (v *VerifiedAuthorization) VerifySourcePath() error {
	if v == nil || v.authorityKey == nil {
		return errors.New("verified exporter authorization is required")
	}
	info, err := os.Stat(v.claims.SourceLedgerPath)
	if err != nil {
		return fmt.Errorf("stat authorized source ledger: %w", err)
	}
	if !info.IsDir() {
		return errors.New("authorized source ledger path is not a directory")
	}
	resolved, err := filepath.EvalSymlinks(v.claims.SourceLedgerPath)
	if err != nil {
		return fmt.Errorf("resolve authorized source ledger path: %w", err)
	}
	if resolved != v.claims.SourceLedgerPath {
		return errors.New("authorized source ledger path resolves through a symlink")
	}
	return nil
}

// SignExecution must be called only by the authority after observing the
// controlled invocation and successful exit of the pinned exporter.
func SignExecution(authorization *VerifiedAuthorization, execution Execution, signer *mldsa.PrivateKey) ([]byte, error) {
	if authorization == nil || authorization.authorityKey == nil || !validSigner(signer) ||
		!bytes.Equal(signer.Public().(*mldsa.PublicKey).Bytes(), authorization.authorityKey.Bytes()) {
		return nil, errors.New("verified authorization and its independent authority signer are required")
	}
	execution.Format = ExecutionFormat
	if err := validateExecution(authorization, execution); err != nil {
		return nil, err
	}
	return sign(executionDomain, execution, signer)
}

func VerifyExecution(authorization *VerifiedAuthorization, encoded []byte) (*VerifiedExecution, error) {
	if authorization == nil || authorization.authorityKey == nil {
		return nil, errors.New("verified exporter authorization is required")
	}
	var execution Execution
	if err := verify(executionDomain, encoded, authorization.authorityKey, &execution); err != nil {
		return nil, fmt.Errorf("verify controlled execution: %w", err)
	}
	if err := validateExecution(authorization, execution); err != nil {
		return nil, err
	}
	return &VerifiedExecution{
		authorizationDigest: execution.AuthorizationDigest,
		evidenceDigest:      execution.ExportEvidenceDigest,
		encoded:             bytes.Clone(encoded),
	}, nil
}

func (v *VerifiedExecution) Matches(authorization *VerifiedAuthorization, evidence []byte) bool {
	return v != nil && authorization != nil && v.authorizationDigest == hash(authorization.encoded) &&
		v.evidenceDigest == hash(evidence)
}

func (v *VerifiedExecution) Encoded() []byte {
	if v == nil {
		return nil
	}
	return bytes.Clone(v.encoded)
}

func validateExecution(authorization *VerifiedAuthorization, execution Execution) error {
	claims := authorization.claims
	if execution.Format != ExecutionFormat || execution.Result != "success" ||
		execution.AuthorizationDigest != hash(authorization.encoded) ||
		execution.ApprovalIdentity != claims.ApprovalIdentity || execution.Generation != claims.Generation ||
		execution.SourceLedgerIdentity != claims.SourceLedgerIdentity || execution.SourceLedgerPath != claims.SourceLedgerPath ||
		execution.Channel != claims.Channel || execution.SnapshotBlockNumber != claims.SnapshotBlockNumber ||
		execution.SnapshotBlockHash != claims.SnapshotBlockHash ||
		execution.ExecutablePath != claims.ExecutablePath || execution.ExecutableSHA256 != claims.ExecutableSHA256 ||
		!validHash(execution.ExportEvidenceDigest) || len(execution.Launcher) == 0 || len(execution.Invocation) == 0 ||
		execution.Invocation[0] != claims.ExecutablePath {
		return errors.New("controlled execution conflicts with exporter authorization")
	}
	for _, args := range [][]string{execution.Launcher, execution.Invocation} {
		for _, arg := range args {
			if !validText(arg) {
				return errors.New("controlled execution contains an invalid invocation")
			}
		}
	}
	return nil
}

func validateAuthorization(c Authorization) error {
	if c.Format != AuthorizationFormat || !validText(c.AuthorityIdentity) ||
		!validHash(c.ApprovalIdentity) || c.Generation == 0 ||
		!validText(c.Network) || !validText(c.Channel) || !validText(c.ExporterIdentity) ||
		!validText(c.SourceLedgerIdentity) || !validPath(c.SourceLedgerPath) || !validPath(c.ExecutablePath) ||
		!validHash(c.ExecutableSHA256) || !validHash(c.TrustedGenesis) ||
		c.ConfigurationSequence == 0 || !validHash(c.ConfigurationDigest) || c.SnapshotBlockNumber == 0 ||
		!validHash(c.SnapshotBlockHash) || !validHash(c.SourceHistoryIdentity) || c.TransportProfile != pqtransport.ProfileV1 {
		return errors.New("exporter authorization is incomplete or unsupported")
	}
	if _, err := mldsa.NewPublicKey(mldsa.MLDSA65(), c.ExporterPublicKey); err != nil {
		return fmt.Errorf("invalid authorized exporter public key: %w", err)
	}
	return nil
}

func validSigner(signer *mldsa.PrivateKey) bool {
	return signer != nil && signer.Public().(*mldsa.PublicKey).Parameters() == mldsa.MLDSA65()
}

func validText(value string) bool {
	return value != "" && value == strings.TrimSpace(value) && !strings.ContainsRune(value, '\x00')
}

func validPath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path &&
		path != filepath.VolumeName(path)+string(filepath.Separator) && !strings.ContainsRune(path, '\x00')
}

func validHash(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && hex.EncodeToString(decoded) == value
}

func hash(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func sign(domain string, value any, signer *mldsa.PrivateKey) ([]byte, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	signature, err := signer.Sign(rand.Reader, append([]byte(domain), payload...), nil)
	if err != nil {
		return nil, err
	}
	return json.Marshal(envelope{Payload: payload, Signature: signature})
}

func verify(domain string, encoded []byte, key *mldsa.PublicKey, out any) error {
	var signed envelope
	if err := decodeCanonical(encoded, &signed); err != nil {
		return err
	}
	if err := mldsa.Verify(key, append([]byte(domain), signed.Payload...), signed.Signature, nil); err != nil {
		return errors.New("signature is invalid")
	}
	return decodeCanonical(signed.Payload, out)
}

func decodeCanonical(encoded []byte, out any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("trailing JSON")
	}
	canonical, err := json.Marshal(out)
	if err != nil {
		return err
	}
	if !bytes.Equal(encoded, canonical) {
		return errors.New("noncanonical JSON")
	}
	return nil
}
