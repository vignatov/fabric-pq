//go:build linux

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
	"fmt"
	"os"
	"path/filepath"
	"testing"

	common "github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation/testfixture"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/enrollment"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/provisioning"
	"github.com/hyperledger/fabric/protoutil"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestRegistryUsesProtectedGenesisForJoinHistory(t *testing.T) {
	fixture := testfixture.New(t)
	genesis := testfixture.Genesis(t)
	config := testfixture.Config(t, genesis)

	stateDir := t.TempDir()
	signerSeed := sha256.Sum256([]byte("PQ4.0E.1 protected registry test signer"))
	signer, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), signerSeed[:])
	require.NoError(t, err)
	publicBytes := signer.Public().(*mldsa.PublicKey).Bytes()
	signerPath := filepath.Join(t.TempDir(), "policy-signer.pub")
	require.NoError(t, os.WriteFile(signerPath, publicBytes, 0o600))
	signerDigest := sha256.Sum256(publicBytes)

	encodedConfig, err := (proto.MarshalOptions{Deterministic: true}).Marshal(config)
	require.NoError(t, err)
	configDigest := sha256.Sum256(encodedConfig)
	document := pqtransport.Document{
		Network: testfixture.Network, Node: testfixture.Node, Version: 1, Profile: pqtransport.ProfileV1,
		Channels: map[string]pqtransport.ChannelBinding{
			testfixture.ChannelID: {Sequence: config.GetSequence(), Digest: hex.EncodeToString(configDigest[:])},
		},
	}
	policyPayload, err := json.Marshal(document)
	require.NoError(t, err)
	policySignature, err := signer.Sign(rand.Reader, policyPayload, nil)
	require.NoError(t, err)
	checkpointDigest := sha256.Sum256(policyPayload)
	store, err := activation.OpenStore(stateDir, nil)
	require.NoError(t, err)
	require.NoError(t, store.Provision(
		pqtransport.Checkpoint{Version: document.Version, Digest: checkpointDigest},
		policyPayload, policySignature,
	))

	channelDigest := sha256.Sum256([]byte(testfixture.ChannelID))
	genesisName := fmt.Sprintf("genesis-%x", channelDigest[:])
	genesisHash := hex.EncodeToString(protoutil.BlockHeaderHash(genesis.GetHeader()))
	encodedGenesisHash, err := json.Marshal(genesisHash)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(stateDir, genesisName), encodedGenesisHash, 0o600))
	rawGenesis, err := proto.Marshal(genesis)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(stateDir, genesisName+".block"), rawGenesis, 0o600))

	manifest := &enrollment.Manifest{
		Network: testfixture.Network, Node: testfixture.Node, Mode: enrollment.Protected,
		Profile: pqtransport.ProfileV1, PolicySigner: signerPath, PolicySignerDigest: hex.EncodeToString(signerDigest[:]),
		StateDir: stateDir, LedgerDir: t.TempDir(),
	}
	registry, err := enrollment.OpenProtectedRegistry(manifest)
	require.NoError(t, err)

	untrustedGenesis := proto.Clone(genesis).(*common.Block)
	untrustedGenesis.Header.DataHash[0] ^= 0xff
	_, err = provisioning.VerifyJoinHistory(registry, testfixture.ChannelID, []*common.Block{untrustedGenesis, genesis}, 1, fixture.Crypto)
	require.ErrorContains(t, err, "independently trusted identity")
}
