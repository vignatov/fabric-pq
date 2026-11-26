/*
SPDX-License-Identifier: Apache-2.0
*/

package provisioning

import (
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/hyperledger/fabric/internal/pkg/pqtransport"
	"github.com/stretchr/testify/require"
)

func TestExporterAuthorizationRequiresIndependentAuthority(t *testing.T) {
	authoritySigner := authorizationTestKey(t, "provisioning authority")
	exporterSigner := authorizationTestKey(t, "approved exporter")
	attackerSigner := authorizationTestKey(t, "attacker exporter")
	authorization := authorizationTestClaims(t, exporterSigner.Public().(*mldsa.PublicKey), t.TempDir())

	encoded, err := SignExporterAuthorization(authorization, authoritySigner)
	require.NoError(t, err)
	verified, err := VerifyExporterAuthorization(encoded, "provisioner-1", authoritySigner.Public().(*mldsa.PublicKey))
	require.NoError(t, err)
	require.NoError(t, verified.VerifyAuthorizedSourcePath())

	copied := verified.Authorization()
	copied.ExporterPublicKey[0] ^= 0xff
	require.NotEqual(t, copied.ExporterPublicKey, verified.Authorization().ExporterPublicKey)

	_, err = VerifyExporterAuthorization(encoded, "attacker-authority", authoritySigner.Public().(*mldsa.PublicKey))
	require.ErrorContains(t, err, "independently trusted authority")
	_, err = VerifyExporterAuthorization(encoded, "provisioner-1", attackerSigner.Public().(*mldsa.PublicKey))
	require.ErrorContains(t, err, "signature is invalid")

	attackerAuthorization := authorizationTestClaims(t, attackerSigner.Public().(*mldsa.PublicKey), t.TempDir())
	attackerEncoded, err := SignExporterAuthorization(attackerAuthorization, attackerSigner)
	require.NoError(t, err)
	_, err = VerifyExporterAuthorization(attackerEncoded, "provisioner-1", authoritySigner.Public().(*mldsa.PublicKey))
	require.ErrorContains(t, err, "signature is invalid")
}

func TestExporterAuthorizationRejectsModifiedAndSubstitutedPaths(t *testing.T) {
	authoritySigner := authorizationTestKey(t, "provisioning authority")
	exporterSigner := authorizationTestKey(t, "approved exporter")
	ledgerA := t.TempDir()
	authorization := authorizationTestClaims(t, exporterSigner.Public().(*mldsa.PublicKey), ledgerA)

	encoded, err := SignExporterAuthorization(authorization, authoritySigner)
	require.NoError(t, err)
	encoded[len(encoded)-1] ^= 1
	_, err = VerifyExporterAuthorization(encoded, "provisioner-1", authoritySigner.Public().(*mldsa.PublicKey))
	require.Error(t, err)

	authorization = authorizationTestClaims(t, exporterSigner.Public().(*mldsa.PublicKey), ledgerA)
	authorization.SourceLedgerPath = filepath.Join(t.TempDir(), "ledger-b")
	missingPath, err := SignExporterAuthorization(authorization, authoritySigner)
	require.NoError(t, err)
	missing, err := VerifyExporterAuthorization(missingPath, "provisioner-1", authoritySigner.Public().(*mldsa.PublicKey))
	require.NoError(t, err)
	require.ErrorIs(t, missing.VerifyAuthorizedSourcePath(), os.ErrNotExist)

	verified, err := VerifyExporterAuthorization(
		mustSignExporterAuthorization(t, authorizationTestClaims(t, exporterSigner.Public().(*mldsa.PublicKey), ledgerA), authoritySigner),
		"provisioner-1",
		authoritySigner.Public().(*mldsa.PublicKey),
	)
	require.NoError(t, err)
	require.NoError(t, verified.VerifyAuthorizedSourcePath())

	replacement := t.TempDir()
	replacementLink := filepath.Join(t.TempDir(), "ledger-b")
	if err := os.Symlink(replacement, replacementLink); err != nil {
		t.Skipf("symlink creation is unavailable: %v", err)
	}
	authorization = verified.Authorization()
	authorization.SourceLedgerPath = replacementLink
	replacementEvidence, err := SignExporterAuthorization(authorization, authoritySigner)
	require.NoError(t, err)
	replaced, err := VerifyExporterAuthorization(
		replacementEvidence,
		"provisioner-1",
		authoritySigner.Public().(*mldsa.PublicKey),
	)
	require.NoError(t, err)
	require.ErrorContains(t, replaced.VerifyAuthorizedSourcePath(), "symlink")
}

func authorizationTestClaims(t *testing.T, exporter *mldsa.PublicKey, sourcePath string) ExporterAuthorization {
	t.Helper()
	return ExporterAuthorization{
		AuthorityIdentity:     "provisioner-1",
		Generation:            4,
		Network:               "network-1",
		Channel:               "channel-1",
		ExporterIdentity:      "approved-exporter",
		ExporterPublicKey:     exporter.Bytes(),
		SourceLedgerIdentity:  "ledger-a",
		SourceLedgerPath:      sourcePath,
		TrustedGenesis:        authorizationTestHash("genesis"),
		ConfigurationSequence: 4,
		ConfigurationDigest:   authorizationTestHash("configuration"),
		SnapshotBlockNumber:   4,
		SnapshotBlockHash:     authorizationTestHash("snapshot-block"),
		SourceHistoryIdentity: authorizationTestHash("history"),
		TransportProfile:      pqtransport.ProfileV1,
	}
}

func authorizationTestKey(t *testing.T, value string) *mldsa.PrivateKey {
	t.Helper()
	seed := sha256.Sum256([]byte(value))
	key, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), seed[:])
	require.NoError(t, err)
	return key
}

func authorizationTestHash(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func mustSignExporterAuthorization(
	t *testing.T,
	authorization ExporterAuthorization,
	signer *mldsa.PrivateKey,
) []byte {
	t.Helper()
	encoded, err := SignExporterAuthorization(authorization, signer)
	require.NoError(t, err)
	return encoded
}
