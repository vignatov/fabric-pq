//go:build linux

/*
SPDX-License-Identifier: Apache-2.0
*/

package enrollment_test

import (
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/hyperledger/fabric/internal/pkg/pqtransport"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation/testfixture"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/enrollment"
	"github.com/stretchr/testify/require"
)

func TestProtectedEnrollmentRequiresRuntimeState(t *testing.T) {
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	fixture := testfixture.New(t)
	dir := t.TempDir()
	store, err := activation.OpenStore(dir, nil)
	require.NoError(t, err)
	fixture.Provision(t, store, testfixture.Config(t, testfixture.Genesis(t)))
	controller := fixture.Channel(store, activation.Ledger{})
	publicBytes := controller.Signer.Bytes()
	keyPath := filepath.Join(t.TempDir(), "policy-key")
	require.NoError(t, os.WriteFile(keyPath, publicBytes, 0o600))
	digest := sha256.Sum256(publicBytes)
	manifest := enrollment.Manifest{
		Network: testfixture.Network, Node: testfixture.Node, Generation: 1, Mode: enrollment.Protected,
		Executable: filepath.Join(t.TempDir(), "orderer"), Profile: pqtransport.ProfileV1,
		PolicySigner: keyPath, PolicySignerDigest: hex.EncodeToString(digest[:]), StateDir: dir, LedgerDir: t.TempDir(),
	}
	signed, history := documents(t, key, manifest, true)
	verified, err := enrollment.Verify(signed, history, key.Public().(*mldsa.PublicKey))
	require.NoError(t, err)
	_, invalidHistory := documents(t, key, manifest, false)
	_, err = enrollment.Verify(signed, invalidHistory, key.Public().(*mldsa.PublicKey))
	require.ErrorContains(t, err, "invalid protected enrollment")
	require.NoError(t, enrollment.AuthenticateProtected(verified))
	require.NoError(t, os.Remove(filepath.Join(dir, "checkpoint")))
	require.ErrorContains(t, enrollment.AuthenticateProtected(verified), "checkpoint")
	require.NoError(t, os.WriteFile(keyPath, []byte("replacement"), 0o600))
	require.ErrorContains(t, enrollment.AuthenticateProtected(verified), "signer conflicts")
}
