//go:build linux

/*
SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/hyperledger/fabric/internal/pkg/pqtransport"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation/testfixture"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/enrollment"
	"github.com/stretchr/testify/require"
)

func signed(t *testing.T, key *mldsa.PrivateKey, domain string, value any) []byte {
	t.Helper()
	payload, err := json.Marshal(value)
	require.NoError(t, err)
	signature, err := key.Sign(rand.Reader, append([]byte(domain), payload...), nil)
	require.NoError(t, err)
	encoded, err := json.Marshal(enrollment.Envelope{Payload: payload, Signature: signature})
	require.NoError(t, err)
	return encoded
}

func TestProtectedLauncherBlocksBeforeExecuting(t *testing.T) {
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	fixture := testfixture.New(t)
	state := t.TempDir()
	store, err := activation.OpenStore(state, nil)
	require.NoError(t, err)
	fixture.Provision(t, store, testfixture.Config(t, testfixture.Genesis(t)))
	controller := fixture.Channel(store, activation.Ledger{})
	dir := t.TempDir()
	signerPath := filepath.Join(dir, "signer")
	signer := controller.Signer.Bytes()
	require.NoError(t, os.WriteFile(signerPath, signer, 0o600))
	signerDigest := sha256.Sum256(signer)
	manifest := enrollment.Manifest{
		Network: testfixture.Network, Node: testfixture.Node, Generation: 1, Mode: enrollment.Protected,
		Executable: "/bin/true", Profile: pqtransport.ProfileV1, PolicySigner: signerPath,
		PolicySignerDigest: hex.EncodeToString(signerDigest[:]), StateDir: state, LedgerDir: t.TempDir(),
	}
	payload, err := json.Marshal(manifest)
	require.NoError(t, err)
	digest := sha256.Sum256(payload)
	history := enrollment.History{Network: manifest.Network, Node: manifest.Node, Generation: 1, ProtectedEver: true, ManifestDigest: hex.EncodeToString(digest[:])}
	authorityPath := filepath.Join(dir, "authority")
	manifestPath := filepath.Join(dir, "manifest")
	historyPath := filepath.Join(dir, "history")
	require.NoError(t, os.WriteFile(authorityPath, key.Public().(*mldsa.PublicKey).Bytes(), 0o600))
	require.NoError(t, os.WriteFile(manifestPath, signed(t, key, "fabric-pq/enrollment/v1\x00", manifest), 0o600))
	require.NoError(t, os.WriteFile(historyPath, signed(t, key, "fabric-pq/enrollment-history/v1\x00", history), 0o600))
	require.ErrorContains(t, run(authorityPath, manifestPath, historyPath), "blocked pending strict transport")
	require.NoError(t, os.Remove(filepath.Join(state, "checkpoint")))
	require.ErrorContains(t, run(authorityPath, manifestPath, historyPath), "checkpoint")
}

func TestLauncherSubprocess(t *testing.T) {
	if os.Getenv("PQ40E_LAUNCHER_CHILD") == "1" {
		if err := run(os.Getenv("PQ40E_AUTHORITY"), os.Getenv("PQ40E_MANIFEST"), os.Getenv("PQ40E_HISTORY")); err != nil {
			os.Exit(2)
		}
		os.Exit(0)
	}
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	dir := t.TempDir()
	authorityPath := filepath.Join(dir, "authority")
	manifestPath := filepath.Join(dir, "manifest")
	historyPath := filepath.Join(dir, "history")
	manifest := enrollment.Manifest{Network: "network", Node: "node", Generation: 1, Mode: enrollment.Baseline, Executable: "/bin/true"}
	payload, err := json.Marshal(manifest)
	require.NoError(t, err)
	digest := sha256.Sum256(payload)
	history := enrollment.History{Network: manifest.Network, Node: manifest.Node, Generation: manifest.Generation, ManifestDigest: hex.EncodeToString(digest[:])}
	require.NoError(t, os.WriteFile(authorityPath, key.Public().(*mldsa.PublicKey).Bytes(), 0o600))
	require.NoError(t, os.WriteFile(manifestPath, signed(t, key, "fabric-pq/enrollment/v1\x00", manifest), 0o600))
	require.NoError(t, os.WriteFile(historyPath, signed(t, key, "fabric-pq/enrollment-history/v1\x00", history), 0o600))
	child := func() error {
		command := exec.Command(os.Args[0], "-test.run=^TestLauncherSubprocess$")
		command.Env = append(os.Environ(), "PQ40E_LAUNCHER_CHILD=1", "PQ40E_AUTHORITY="+authorityPath, "PQ40E_MANIFEST="+manifestPath, "PQ40E_HISTORY="+historyPath)
		return command.Run()
	}
	require.NoError(t, child())
	require.NoError(t, os.Remove(manifestPath))
	require.Error(t, child())
	require.NoError(t, os.WriteFile(manifestPath, []byte("corrupt"), 0o600))
	require.Error(t, child())
}
