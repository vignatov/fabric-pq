/*
SPDX-License-Identifier: Apache-2.0
*/

package pqtransport

import (
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"

	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	"google.golang.org/protobuf/proto"
)

// TransitionDocument is the operator's separate authorization for one
// channel configuration and one policy/checkpoint advance.
type TransitionDocument struct {
	Network           string `json:"network"`
	Node              string `json:"node"`
	Channel           string `json:"channel"`
	PreviousVersion   uint64 `json:"previous_version"`
	PreviousDigest    string `json:"previous_digest"`
	NewVersion        uint64 `json:"new_version"`
	NewPolicyDigest   string `json:"new_policy_digest"`
	NewConfigSequence uint64 `json:"new_config_sequence"`
	NewConfigDigest   string `json:"new_config_digest"`
	Profile           string `json:"profile"`
}

// VerifyOperatorTransition checks operator authorization only. The caller must
// separately validate the Fabric update and capability before activation, and
// must durably commit or recover the checkpoint; this function does neither.
func VerifyOperatorTransition(
	current *Policy,
	transition, transitionSignature, newPolicy, newPolicySignature []byte,
	signer *mldsa.PublicKey,
	config *cb.Config,
) (*Policy, error) {
	if err := current.Check(); err != nil {
		return nil, err
	}
	if signer == nil || signer.Parameters() != mldsa.MLDSA65() ||
		sha256.Sum256(signer.Bytes()) != current.signerDigest {
		return nil, errors.New("transition signer is not the trusted policy signer")
	}
	if len(transition) == 0 || len(transitionSignature) == 0 || len(newPolicy) == 0 || len(newPolicySignature) == 0 || config == nil {
		return nil, errors.New("missing transition, policy, signature or channel configuration")
	}
	if err := mldsa.Verify(signer, transition, transitionSignature, nil); err != nil {
		return nil, fmt.Errorf("transition signature verification: %w", err)
	}
	var authorization TransitionDocument
	if err := decodeCanonical(transition, &authorization); err != nil {
		return nil, fmt.Errorf("decode transition: %w", err)
	}
	if authorization.Network != current.document.Network || authorization.Node != current.document.Node {
		return nil, errors.New("transition network or node conflicts with current policy")
	}
	if authorization.Profile != ProfileV1 {
		return nil, errors.New("transition attempts to weaken the transport profile")
	}
	if authorization.PreviousVersion != current.document.Version ||
		authorization.PreviousDigest != hex.EncodeToString(current.digest[:]) {
		return nil, errors.New("transition previous checkpoint conflicts with current policy")
	}
	if current.document.Version == math.MaxUint64 || authorization.NewVersion != current.document.Version+1 {
		return nil, errors.New("transition checkpoint version is not the next version")
	}
	newDigest := sha256.Sum256(newPolicy)
	if authorization.NewPolicyDigest != hex.EncodeToString(newDigest[:]) {
		return nil, errors.New("transition new policy digest conflicts")
	}
	next, err := Authenticate(newPolicy, newPolicySignature, signer,
		&Checkpoint{Version: authorization.NewVersion, Digest: newDigest},
		current.document.Network, current.document.Node)
	if err != nil {
		return nil, fmt.Errorf("new policy: %w", err)
	}

	oldBinding, ok := current.document.Channels[authorization.Channel]
	if !ok {
		return nil, errors.New("transition channel is not bound to current policy")
	}
	newBinding, ok := next.document.Channels[authorization.Channel]
	if !ok || len(next.document.Channels) != len(current.document.Channels) {
		return nil, errors.New("transition changes unrelated channel bindings")
	}
	for channel, old := range current.document.Channels {
		if channel != authorization.Channel && next.document.Channels[channel] != old {
			return nil, errors.New("transition changes unrelated channel bindings")
		}
	}
	if oldBinding.Sequence == math.MaxUint64 || authorization.NewConfigSequence != oldBinding.Sequence+1 ||
		config.GetSequence() != authorization.NewConfigSequence || newBinding.Sequence != authorization.NewConfigSequence {
		return nil, errors.New("transition channel configuration sequence is not the next sequence")
	}
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("marshal channel configuration: %w", err)
	}
	configDigest := sha256.Sum256(encoded)
	if authorization.NewConfigDigest != hex.EncodeToString(configDigest[:]) || newBinding.Digest != authorization.NewConfigDigest {
		return nil, errors.New("transition channel configuration digest conflicts")
	}
	return next, nil
}
