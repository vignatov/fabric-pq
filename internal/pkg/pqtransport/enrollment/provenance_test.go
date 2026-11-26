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
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/provenance"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/provisioning"
	"github.com/hyperledger/fabric/protoutil"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestRegistryUsesProtectedGenesisForJoinHistory(t *testing.T) {
	fixture := testfixture.New(t)
	genesis := fixture.RaftGenesis(t)
	update := fixture.Update(t, testfixture.Config(t, genesis))
	target := fixture.SignedBlock(t, genesis, fixture.Envelope(t, update), 1)
	config := update.GetConfig()

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

	verified, err := provisioning.VerifyJoinHistory(registry, testfixture.ChannelID, []*common.Block{genesis, target}, 1, fixture.Crypto)
	require.NoError(t, err)
	signed, err := provisioning.SignVerifiedOrdererJoinAnchor(verified, signer)
	require.NoError(t, err)
	var envelope enrollment.Envelope
	require.NoError(t, json.Unmarshal(signed, &envelope))
	require.NoError(t, mldsa.Verify(signer.Public().(*mldsa.PublicKey), append([]byte(enrollment.OrdererJoinAnchorDomain), envelope.Payload...), envelope.Signature, nil))
	otherSeed := sha256.Sum256([]byte("unrelated provenance signer"))
	otherSigner, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), otherSeed[:])
	require.NoError(t, err)
	_, err = provisioning.SignVerifiedOrdererJoinAnchor(verified, otherSigner)
	require.ErrorContains(t, err, "does not match the authenticated")
	_, err = provisioning.SignVerifiedOrdererJoinAnchor(&provisioning.VerifiedJoinHistory{}, signer)
	require.ErrorContains(t, err, "verified Fabric provenance")
	_, err = provisioning.SignVerifiedOrdererJoinAnchor(nil, signer)
	require.ErrorContains(t, err, "verified Fabric provenance")

	_, err = provisioning.SignVerifiedPeerSnapshotAnchor(verified, nil, signer)
	require.ErrorContains(t, err, "verified staged snapshot export")

	alternateGenesis := fixture.RaftGenesis(t)
	alternateUpdate := fixture.Update(t, testfixture.Config(t, alternateGenesis))
	alternateTarget := fixture.SignedBlock(t, alternateGenesis, fixture.Envelope(t, alternateUpdate), 1)
	alternateHistory := []*common.Block{alternateGenesis, alternateTarget}
	alternateConfig, err := (proto.MarshalOptions{Deterministic: true}).Marshal(alternateUpdate.GetConfig())
	require.NoError(t, err)
	alternateDigest := sha256.Sum256(alternateConfig)
	alternateDocument := pqtransport.Document{
		Network: testfixture.Network, Node: testfixture.Node, Version: 1, Profile: pqtransport.ProfileV1,
		Channels: map[string]pqtransport.ChannelBinding{
			testfixture.ChannelID: {Sequence: alternateUpdate.GetConfig().GetSequence(), Digest: hex.EncodeToString(alternateDigest[:])},
		},
	}
	alternatePayload, err := json.Marshal(alternateDocument)
	require.NoError(t, err)
	alternateSignature, err := signer.Sign(rand.Reader, alternatePayload, nil)
	require.NoError(t, err)
	alternateCheckpoint := pqtransport.Checkpoint{Version: 1, Digest: sha256.Sum256(alternatePayload)}
	alternatePolicy, err := pqtransport.Authenticate(
		alternatePayload, alternateSignature, signer.Public().(*mldsa.PublicKey), &alternateCheckpoint,
		testfixture.Network, testfixture.Node,
	)
	require.NoError(t, err)
	generic, err := provenance.VerifyHistory(provenance.Request{
		Network: testfixture.Network, Node: testfixture.Node, Channel: testfixture.ChannelID,
		TrustedGenesisHash: hex.EncodeToString(protoutil.BlockHeaderHash(alternateGenesis.GetHeader())),
		TargetBlockNumber:  1, History: alternateHistory, Policy: alternatePolicy, Crypto: fixture.Crypto,
	})
	require.NoError(t, err)
	require.True(t, generic.Verified())
	require.True(t, generic.MatchesSigner(signer.Public().(*mldsa.PublicKey)))
	_, signable := any(generic).(*provisioning.VerifiedJoinHistory)
	require.False(t, signable, "a generic verification result must not be a signable registry-bound token")
	foreign, err := provisioning.VerifyJoinHistory(registry, testfixture.ChannelID, alternateHistory, 1, fixture.Crypto)
	require.Nil(t, foreign)
	require.ErrorContains(t, err, "independently trusted identity")
	_, err = provisioning.SignVerifiedOrdererJoinAnchor(foreign, signer)
	require.ErrorContains(t, err, "verified Fabric provenance")
	_, err = provisioning.SignVerifiedPeerSnapshotAnchor(foreign, nil, signer)
	require.ErrorContains(t, err, "verified Fabric provenance")
}
