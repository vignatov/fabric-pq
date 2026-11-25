/*
SPDX-License-Identifier: Apache-2.0
*/

// Package enrollment verifies VM provisioning evidence independently of
// ordinary Fabric configuration. It does not itself enforce service-manager
// permissions or authenticate a channel's ledger.
package enrollment

import (
	"bytes"
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/hyperledger/fabric-lib-go/bccsp"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation"
)

const (
	Baseline  = "BASELINE"
	Protected = "PROTECTED"
)

// Manifest is the provisioning authority's complete managed-service decision.
type Manifest struct {
	Network            string   `json:"network"`
	Node               string   `json:"node"`
	Mode               string   `json:"mode"`
	Generation         uint64   `json:"generation"`
	Executable         string   `json:"executable"`
	Arguments          []string `json:"arguments"`
	Profile            string   `json:"profile"`
	PolicySigner       string   `json:"policy_signer"`
	PolicySignerDigest string   `json:"policy_signer_digest"`
	StateDir           string   `json:"state_dir"`
	LedgerDir          string   `json:"ledger_dir"`
}

// History is stored independently of runtime state and pins the exact
// manifest. Provisioning must never clear ProtectedEver after enrollment.
type History struct {
	Network        string `json:"network"`
	Node           string `json:"node"`
	Generation     uint64 `json:"generation"`
	ProtectedEver  bool   `json:"protected_ever"`
	ManifestDigest string `json:"manifest_digest"`
}

// Envelope signs canonical JSON bytes with the provisioner's ML-DSA-65 key.
type Envelope struct {
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

func decodeCanonical(data []byte, out any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
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
	if !bytes.Equal(data, canonical) {
		return errors.New("noncanonical JSON")
	}
	return nil
}

func verify(data []byte, key *mldsa.PublicKey, domain string, out any) ([]byte, error) {
	var envelope Envelope
	if key == nil || key.Parameters() != mldsa.MLDSA65() {
		return nil, errors.New("invalid provisioning authority")
	}
	if err := decodeCanonical(data, &envelope); err != nil {
		return nil, err
	}
	message := append([]byte(domain), envelope.Payload...)
	if err := mldsa.Verify(key, message, envelope.Signature, nil); err != nil {
		return nil, err
	}
	if err := decodeCanonical(envelope.Payload, out); err != nil {
		return nil, err
	}
	return envelope.Payload, nil
}

// Verify checks independently signed manifest and history. Neither an absent
// manifest nor absent history grants baseline operation.
func Verify(manifestBytes, historyBytes []byte, authority *mldsa.PublicKey) (*Manifest, error) {
	var manifest Manifest
	payload, err := verify(manifestBytes, authority, "fabric-pq/enrollment/v1\x00", &manifest)
	if err != nil {
		return nil, fmt.Errorf("verify enrollment manifest: %w", err)
	}
	var history History
	if _, err := verify(historyBytes, authority, "fabric-pq/enrollment-history/v1\x00", &history); err != nil {
		return nil, fmt.Errorf("verify enrollment history: %w", err)
	}
	digest := sha256.Sum256(payload)
	if manifest.Network == "" || manifest.Node == "" || strings.TrimSpace(manifest.Network) != manifest.Network || strings.TrimSpace(manifest.Node) != manifest.Node ||
		manifest.Generation == 0 || manifest.Network != history.Network || manifest.Node != history.Node || manifest.Generation != history.Generation ||
		history.ManifestDigest != hex.EncodeToString(digest[:]) {
		return nil, errors.New("manifest conflicts with protected enrollment history")
	}
	if !filepath.IsAbs(manifest.Executable) || filepath.Clean(manifest.Executable) != manifest.Executable {
		return nil, errors.New("executable must be an absolute clean path")
	}
	switch manifest.Mode {
	case Baseline:
		if history.ProtectedEver {
			return nil, errors.New("protected enrollment cannot return to baseline")
		}
		if manifest.Profile != "" || manifest.PolicySigner != "" || manifest.PolicySignerDigest != "" || manifest.StateDir != "" || manifest.LedgerDir != "" {
			return nil, errors.New("baseline manifest contains protected settings")
		}
	case Protected:
		if !history.ProtectedEver || manifest.Profile != pqtransport.ProfileV1 || !filepath.IsAbs(manifest.PolicySigner) || !filepath.IsAbs(manifest.StateDir) || !filepath.IsAbs(manifest.LedgerDir) ||
			filepath.Clean(manifest.PolicySigner) != manifest.PolicySigner || filepath.Clean(manifest.StateDir) != manifest.StateDir || filepath.Clean(manifest.LedgerDir) != manifest.LedgerDir {
			return nil, errors.New("invalid protected enrollment settings")
		}
		raw, err := hex.DecodeString(manifest.PolicySignerDigest)
		if err != nil || len(raw) != sha256.Size || hex.EncodeToString(raw) != manifest.PolicySignerDigest {
			return nil, errors.New("invalid policy signer digest")
		}
	default:
		return nil, errors.New("unknown enrollment mode")
	}
	return &manifest, nil
}

// AuthenticateProtected validates runtime security state against the signer
// and identity pinned by the manifest. Channel recovery remains mandatory.
func AuthenticateProtected(manifest *Manifest) error {
	_, err := OpenProtectedRegistry(manifest)
	return err
}

// Registry selects channels from the authenticated checkpoint on a protected
// node. It is constructed from an independently verified enrollment manifest.
type Registry struct {
	store    *activation.Store
	key      *mldsa.PublicKey
	policy   *pqtransport.Policy
	network  string
	node     string
	root     string
	stateDir string
}

// OpenProtectedRegistry validates protection state and retains the store used
// by all controllers on this node. The caller must verify the manifest first.
func OpenProtectedRegistry(manifest *Manifest) (*Registry, error) {
	if manifest == nil || manifest.Mode != Protected {
		return nil, errors.New("protected manifest required")
	}
	raw, err := os.ReadFile(manifest.PolicySigner)
	if err != nil {
		return nil, fmt.Errorf("read policy signer: %w", err)
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != manifest.PolicySignerDigest {
		return nil, errors.New("policy signer conflicts with manifest")
	}
	key, err := mldsa.NewPublicKey(mldsa.MLDSA65(), raw)
	if err != nil {
		return nil, fmt.Errorf("parse policy signer: %w", err)
	}
	store, err := activation.OpenStore(manifest.StateDir, nil)
	if err != nil {
		return nil, fmt.Errorf("open protected state: %w", err)
	}
	policy, err := store.AuthenticateRegistry(key, manifest.Network, manifest.Node)
	if err != nil {
		return nil, err
	}
	return &Registry{
		store: store, key: key, policy: policy, network: manifest.Network,
		node: manifest.Node, root: manifest.LedgerDir, stateDir: manifest.StateDir,
	}, nil
}

// LedgerRoot is the ledger directory pinned by the enrollment manifest.
func (r *Registry) LedgerRoot() string {
	return r.root
}

// TransportPolicy is the authenticated floor applied to shared transports.
func (r *Registry) TransportPolicy() *pqtransport.Policy {
	return r.policy
}

// Controller returns a closed controller for an enrolled channel. A nil result
// means the authenticated checkpoint has no binding for the channel.
func (r *Registry) Controller(id string, crypto bccsp.BCCSP) *activation.Channel {
	if !r.RequiresProtection(id) {
		return nil
	}
	return &activation.Channel{
		ID: id, Network: r.network, Node: r.node, Signer: r.key,
		Store: r.store, Gate: &activation.Gate{}, Crypto: crypto,
	}
}

// RequiresProtection reports the authenticated channel selection.
func (r *Registry) RequiresProtection(id string) bool {
	_, ok := r.policy.Channel(id)
	return ok
}
