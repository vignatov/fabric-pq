/*
SPDX-License-Identifier: Apache-2.0
*/

package enrollment_test

import (
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/hyperledger/fabric/internal/pkg/pqtransport/enrollment"
	"github.com/stretchr/testify/require"
)

func sign(t *testing.T, key *mldsa.PrivateKey, domain string, value any) []byte {
	t.Helper()
	payload, err := json.Marshal(value)
	require.NoError(t, err)
	signature, err := key.Sign(rand.Reader, append([]byte(domain), payload...), nil)
	require.NoError(t, err)
	encoded, err := json.Marshal(enrollment.Envelope{Payload: payload, Signature: signature})
	require.NoError(t, err)
	return encoded
}

func documents(t *testing.T, key *mldsa.PrivateKey, manifest enrollment.Manifest, protectedEver bool) ([]byte, []byte) {
	t.Helper()
	payload, err := json.Marshal(manifest)
	require.NoError(t, err)
	digest := sha256.Sum256(payload)
	history := enrollment.History{
		Network: manifest.Network, Node: manifest.Node, Generation: manifest.Generation,
		ProtectedEver: protectedEver, ManifestDigest: hex.EncodeToString(digest[:]),
	}
	return sign(t, key, "fabric-pq/enrollment/v1\x00", manifest), sign(t, key, "fabric-pq/enrollment-history/v1\x00", history)
}

func TestEnrollmentManifestAndHistory(t *testing.T) {
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	public := key.Public().(*mldsa.PublicKey)
	baseline := enrollment.Manifest{Network: "network", Node: "node", Generation: 1, Mode: enrollment.Baseline, Executable: filepath.Join(t.TempDir(), "peer")}
	manifest, history := documents(t, key, baseline, false)
	got, err := enrollment.Verify(manifest, history, public)
	require.NoError(t, err)
	require.Equal(t, enrollment.Baseline, got.Mode)
	_, err = enrollment.Verify(nil, history, public)
	require.Error(t, err)
	_, err = enrollment.Verify(manifest, nil, public)
	require.Error(t, err)
	corrupt := append([]byte(nil), manifest...)
	corrupt[len(corrupt)-2] ^= 1
	_, err = enrollment.Verify(corrupt, history, public)
	require.Error(t, err)
	other, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	_, err = enrollment.Verify(manifest, history, other.Public().(*mldsa.PublicKey))
	require.Error(t, err)
	_, previousProtected := documents(t, key, baseline, true)
	_, err = enrollment.Verify(manifest, previousProtected, public)
	require.ErrorContains(t, err, "cannot return to baseline")
	changed := baseline
	changed.Node = "other"
	replacement, _ := documents(t, key, changed, false)
	_, err = enrollment.Verify(replacement, history, public)
	require.ErrorContains(t, err, "conflicts")
	changed = baseline
	changed.Generation++
	replacement, _ = documents(t, key, changed, false)
	_, err = enrollment.Verify(replacement, history, public)
	require.ErrorContains(t, err, "conflicts")
}
