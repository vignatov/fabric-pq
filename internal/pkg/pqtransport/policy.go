/*
SPDX-License-Identifier: Apache-2.0
*/

// Package pqtransport contains the isolated-development PQ transport policy.
package pqtransport

import (
	"bytes"
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"strings"
)

const ProfileV1 = "pactway-pq-tls-v1"

// ChannelBinding identifies the authenticated configuration approved for a channel.
type ChannelBinding struct {
	Sequence uint64 `json:"sequence"`
	Digest   string `json:"digest"`
}

// Document is the signed representation of a node's transport policy.
type Document struct {
	Network  string                    `json:"network"`
	Node     string                    `json:"node"`
	Version  uint64                    `json:"version"`
	Profile  string                    `json:"profile"`
	Channels map[string]ChannelBinding `json:"channels"`
}

// Checkpoint is supplied from operator-protected local state.
type Checkpoint struct {
	Version uint64
	Digest  [sha256.Size]byte
}

// Policy can only be obtained by authenticating a document against a checkpoint.
type Policy struct {
	document     Document
	digest       [sha256.Size]byte
	signerDigest [sha256.Size]byte
	valid        bool
}

// Authenticate verifies a signed policy against the trusted signer, checkpoint
// and independently provisioned node identity. It does not update the checkpoint.
func Authenticate(payload, signature []byte, signer *mldsa.PublicKey, checkpoint *Checkpoint, network, node string) (*Policy, error) {
	if len(payload) == 0 || len(signature) == 0 || signer == nil || checkpoint == nil || network == "" || node == "" {
		return nil, errors.New("missing policy, signature, trust anchor, checkpoint, network or node")
	}
	if strings.TrimSpace(network) != network || strings.TrimSpace(node) != node {
		return nil, errors.New("invalid bootstrap network or node identity")
	}
	if signer.Parameters() != mldsa.MLDSA65() {
		return nil, errors.New("policy signer must use ML-DSA-65")
	}
	if err := mldsa.Verify(signer, payload, signature, nil); err != nil {
		return nil, fmt.Errorf("policy signature verification: %w", err)
	}

	var document Document
	if err := decodeCanonical(payload, &document); err != nil {
		return nil, fmt.Errorf("decode policy: %w", err)
	}
	if document.Network != network || document.Node != node {
		return nil, errors.New("policy network or node conflicts with bootstrap identity")
	}
	if document.Profile != ProfileV1 {
		return nil, errors.New("policy transport profile is not approved")
	}
	if document.Version == 0 || checkpoint.Version != document.Version {
		return nil, errors.New("policy version conflicts with protected checkpoint")
	}
	digest := sha256.Sum256(payload)
	if digest != checkpoint.Digest {
		return nil, errors.New("policy digest conflicts with protected checkpoint")
	}
	for channel, binding := range document.Channels {
		if strings.TrimSpace(channel) == "" {
			return nil, errors.New("policy contains an empty channel ID")
		}
		decoded, err := hex.DecodeString(binding.Digest)
		if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != binding.Digest {
			return nil, fmt.Errorf("invalid configuration digest for channel %q", channel)
		}
	}
	return &Policy{
		document:     document,
		digest:       digest,
		signerDigest: sha256.Sum256(signer.Bytes()),
		valid:        true,
	}, nil
}

func decodeCanonical(payload []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("contains trailing data")
	}
	canonical, err := json.Marshal(target)
	if err != nil {
		return err
	}
	if !bytes.Equal(payload, canonical) {
		return errors.New("not canonical JSON")
	}
	return nil
}

// Check ensures a policy was authenticated before it is used.
func (p *Policy) Check() error {
	if p == nil || !p.valid || p.document.Profile != ProfileV1 {
		return errors.New("authenticated PQ transport policy is required")
	}
	return nil
}

// Network returns the network identity from an authenticated policy.
func (p *Policy) Network() string {
	if p.Check() != nil {
		return ""
	}
	return p.document.Network
}

// Node returns the node identity from an authenticated policy.
func (p *Policy) Node() string {
	if p.Check() != nil {
		return ""
	}
	return p.document.Node
}

// Profile returns the transport profile from an authenticated policy.
func (p *Policy) Profile() string {
	if p.Check() != nil {
		return ""
	}
	return p.document.Profile
}

// SignerMatches reports whether key is the public half of the authenticated
// policy-signing key.
func (p *Policy) SignerMatches(key *mldsa.PublicKey) bool {
	if p.Check() != nil || key == nil || key.Parameters() != mldsa.MLDSA65() {
		return false
	}
	return p.signerDigest == sha256.Sum256(key.Bytes())
}

// Channel returns the binding approved by the authenticated policy.
func (p *Policy) Channel(channel string) (ChannelBinding, bool) {
	if p.Check() != nil {
		return ChannelBinding{}, false
	}
	binding, ok := p.document.Channels[channel]
	return binding, ok
}

// Channels returns a copy of the bindings in an authenticated policy.
// Mutating the result cannot alter the policy or its security decisions.
func (p *Policy) Channels() (map[string]ChannelBinding, error) {
	if err := p.Check(); err != nil {
		return nil, err
	}
	return maps.Clone(p.document.Channels), nil
}

// Checkpoint returns the checkpoint corresponding to the authenticated policy.
func (p *Policy) Checkpoint() (Checkpoint, error) {
	if err := p.Check(); err != nil {
		return Checkpoint{}, err
	}
	return Checkpoint{Version: p.document.Version, Digest: p.digest}, nil
}
