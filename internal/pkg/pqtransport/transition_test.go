/*
SPDX-License-Identifier: Apache-2.0
*/

package pqtransport

import (
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestVerifyOperatorTransition(t *testing.T) {
	signer, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	public, ok := signer.Public().(*mldsa.PublicKey)
	require.True(t, ok)
	otherSigner, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	otherPublic, ok := otherSigner.Public().(*mldsa.PublicKey)
	require.True(t, ok)

	sign := func(value any) ([]byte, []byte) {
		payload, err := json.Marshal(value)
		require.NoError(t, err)
		signature, err := signer.Sign(rand.Reader, payload, nil)
		require.NoError(t, err)
		return payload, signature
	}
	digest := func(b []byte) string {
		d := sha256.Sum256(b)
		return hex.EncodeToString(d[:])
	}
	config := &cb.Config{Sequence: 4}
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(config)
	require.NoError(t, err)
	nextConfigDigest := digest(encoded)
	currentDoc := Document{
		Network: "network", Node: "node", Version: 2, Profile: ProfileV1,
		Channels: map[string]ChannelBinding{"channel": {Sequence: 3, Digest: digest([]byte("previous config"))}},
	}
	currentPayload, currentSignature := sign(currentDoc)
	current, err := Authenticate(currentPayload, currentSignature, public,
		&Checkpoint{Version: 2, Digest: sha256.Sum256(currentPayload)}, "network", "node")
	require.NoError(t, err)
	nextDoc := Document{
		Network: "network", Node: "node", Version: 3, Profile: ProfileV1,
		Channels: map[string]ChannelBinding{"channel": {Sequence: 4, Digest: nextConfigDigest}},
	}
	nextPayload, nextSignature := sign(nextDoc)
	authorization := TransitionDocument{
		Network: "network", Node: "node", Channel: "channel", PreviousVersion: 2,
		PreviousDigest: digest(currentPayload), NewVersion: 3, NewPolicyDigest: digest(nextPayload),
		NewConfigSequence: 4, NewConfigDigest: nextConfigDigest, Profile: ProfileV1,
	}
	transition, transitionSignature := sign(authorization)
	verify := func(current *Policy, auth TransitionDocument, candidate Document, actual *cb.Config) (*Policy, error) {
		t.Helper()
		policyPayload, policySignature := sign(candidate)
		auth.NewPolicyDigest = digest(policyPayload)
		transitionPayload, signature := sign(auth)
		return VerifyOperatorTransition(current, transitionPayload, signature, policyPayload, policySignature, public, actual)
	}

	next, err := VerifyOperatorTransition(current, transition, transitionSignature, nextPayload, nextSignature, public, config)
	require.NoError(t, err)
	binding, found := next.Channel("channel")
	require.True(t, found)
	require.Equal(t, uint64(4), binding.Sequence)
	original, found := current.Channel("channel")
	require.True(t, found)
	require.Equal(t, uint64(3), original.Sequence, "verification must not advance the current checkpoint")

	t.Run("replayed transition", func(t *testing.T) {
		_, err := VerifyOperatorTransition(next, transition, transitionSignature, nextPayload, nextSignature, public, config)
		require.ErrorContains(t, err, "previous checkpoint conflicts")
	})
	t.Run("unauthorized signer", func(t *testing.T) {
		_, err := VerifyOperatorTransition(current, transition, transitionSignature, nextPayload, nextSignature, otherPublic, config)
		require.ErrorContains(t, err, "not the trusted policy signer")
	})
	t.Run("invalid signature", func(t *testing.T) {
		bad := append([]byte(nil), transitionSignature...)
		bad[0] ^= 1
		_, err := VerifyOperatorTransition(current, transition, bad, nextPayload, nextSignature, public, config)
		require.ErrorContains(t, err, "transition signature verification")
	})
	t.Run("wrong checkpoint", func(t *testing.T) {
		changed := authorization
		changed.PreviousDigest = digest([]byte("conflict"))
		_, err := verify(current, changed, nextDoc, config)
		require.ErrorContains(t, err, "previous checkpoint conflicts")
	})
	t.Run("skipped checkpoint", func(t *testing.T) {
		changed := authorization
		changed.NewVersion++
		_, err := verify(current, changed, nextDoc, config)
		require.ErrorContains(t, err, "not the next version")
	})
	t.Run("weakened profile", func(t *testing.T) {
		changed := authorization
		changed.Profile = "classical"
		_, err := verify(current, changed, nextDoc, config)
		require.ErrorContains(t, err, "weaken the transport profile")
		weakPolicy := nextDoc
		weakPolicy.Profile = "classical"
		_, err = verify(current, authorization, weakPolicy, config)
		require.ErrorContains(t, err, "profile is not approved")
	})
	t.Run("changed channel configuration", func(t *testing.T) {
		changed := &cb.Config{Sequence: 4, ChannelGroup: &cb.ConfigGroup{}}
		_, err := verify(current, authorization, nextDoc, changed)
		require.ErrorContains(t, err, "configuration digest conflicts")
	})
	t.Run("skipped channel sequence", func(t *testing.T) {
		changed := authorization
		changed.NewConfigSequence++
		_, err := verify(current, changed, nextDoc, &cb.Config{Sequence: 5})
		require.ErrorContains(t, err, "not the next sequence")
	})
	t.Run("unrelated binding change", func(t *testing.T) {
		changed := nextDoc
		changed.Channels = map[string]ChannelBinding{
			"channel": nextDoc.Channels["channel"],
			"other":   {Digest: digest([]byte("other"))},
		}
		_, err := verify(current, authorization, changed, config)
		require.ErrorContains(t, err, "unrelated channel bindings")
	})
}
