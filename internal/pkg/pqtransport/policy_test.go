/*
SPDX-License-Identifier: Apache-2.0
*/

package pqtransport

import (
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAuthenticate(t *testing.T) {
	signer, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	public, ok := signer.Public().(*mldsa.PublicKey)
	require.True(t, ok)
	other, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	otherPublic, ok := other.Public().(*mldsa.PublicKey)
	require.True(t, ok)

	document := Document{
		Network: "network-a",
		Node:    "node-a",
		Version: 2,
		Profile: ProfileV1,
		Channels: map[string]ChannelBinding{
			"channel-a": {Sequence: 4, Digest: strings.Repeat("ab", sha256.Size)},
		},
	}
	sign := func(t *testing.T, doc Document) ([]byte, []byte, *Checkpoint) {
		t.Helper()
		payload, err := json.Marshal(doc)
		require.NoError(t, err)
		signature, err := signer.Sign(rand.Reader, payload, nil)
		require.NoError(t, err)
		return payload, signature, &Checkpoint{Version: doc.Version, Digest: sha256.Sum256(payload)}
	}
	payload, signature, checkpoint := sign(t, document)

	policy, err := Authenticate(payload, signature, public, checkpoint, "network-a", "node-a")
	require.NoError(t, err)
	require.NoError(t, policy.Check())
	binding, found := policy.Channel("channel-a")
	require.True(t, found)
	require.Equal(t, document.Channels["channel-a"], binding)
	_, found = policy.Channel("channel-b")
	require.False(t, found)
	gotCheckpoint, err := policy.Checkpoint()
	require.NoError(t, err)
	require.Equal(t, *checkpoint, gotCheckpoint)
	require.ErrorContains(t, (&Policy{}).Check(), "authenticated")

	t.Run("bootstrap rejects invalid inputs", func(t *testing.T) {
		staleCheckpoint := *checkpoint
		staleCheckpoint.Version++
		conflictingCheckpoint := *checkpoint
		conflictingCheckpoint.Digest[0] ^= 1
		tampered := append([]byte(nil), payload...)
		tampered[0] ^= 1

		for _, test := range []struct {
			name       string
			payload    []byte
			signature  []byte
			signer     *mldsa.PublicKey
			checkpoint *Checkpoint
			network    string
			node       string
			cause      string
		}{
			{"missing policy", nil, signature, public, checkpoint, "network-a", "node-a", "missing policy"},
			{"missing checkpoint", payload, signature, public, nil, "network-a", "node-a", "checkpoint"},
			{"untrusted signer", payload, signature, otherPublic, checkpoint, "network-a", "node-a", "signature verification"},
			{"tampered policy", tampered, signature, public, checkpoint, "network-a", "node-a", "signature verification"},
			{"wrong network", payload, signature, public, checkpoint, "network-b", "node-a", "bootstrap identity"},
			{"wrong node", payload, signature, public, checkpoint, "network-a", "node-b", "bootstrap identity"},
			{"invalid node", payload, signature, public, checkpoint, "network-a", " ", "invalid bootstrap"},
			{"stale version", payload, signature, public, &staleCheckpoint, "network-a", "node-a", "version conflicts"},
			{"conflicting digest", payload, signature, public, &conflictingCheckpoint, "network-a", "node-a", "digest conflicts"},
		} {
			t.Run(test.name, func(t *testing.T) {
				_, err := Authenticate(test.payload, test.signature, test.signer, test.checkpoint, test.network, test.node)
				require.ErrorContains(t, err, test.cause)
			})
		}
	})

	t.Run("signed weakening and invalid binding", func(t *testing.T) {
		weak := document
		weak.Profile = "classical"
		weakPayload, weakSignature, weakCheckpoint := sign(t, weak)
		_, err := Authenticate(weakPayload, weakSignature, public, weakCheckpoint, "network-a", "node-a")
		require.ErrorContains(t, err, "profile is not approved")

		invalid := document
		invalid.Channels = map[string]ChannelBinding{"channel-a": {Digest: "bad"}}
		invalidPayload, invalidSignature, invalidCheckpoint := sign(t, invalid)
		_, err = Authenticate(invalidPayload, invalidSignature, public, invalidCheckpoint, "network-a", "node-a")
		require.ErrorContains(t, err, "invalid configuration digest")
	})

	t.Run("signed noncanonical policy", func(t *testing.T) {
		noncanonical := append([]byte(" "), payload...)
		noncanonicalSignature, err := signer.Sign(rand.Reader, noncanonical, nil)
		require.NoError(t, err)
		noncanonicalCheckpoint := &Checkpoint{Version: document.Version, Digest: sha256.Sum256(noncanonical)}
		_, err = Authenticate(noncanonical, noncanonicalSignature, public, noncanonicalCheckpoint, "network-a", "node-a")
		require.ErrorContains(t, err, "not canonical")
	})
}
