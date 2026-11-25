//go:build linux

/*
SPDX-License-Identifier: Apache-2.0
*/

package peer

import (
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	pb "github.com/hyperledger/fabric-protos-go-apiv2/peer"
	"github.com/hyperledger/fabric/common/util"
	"github.com/hyperledger/fabric/core/ledger"
	"github.com/hyperledger/fabric/core/ledger/kvledger"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation/testfixture"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/enrollment"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/provisioning"
	"github.com/hyperledger/fabric/protoutil"
	"github.com/stretchr/testify/require"
)

func TestPQ40ESignedNonGenesisSnapshotJoinAndRecovery(t *testing.T) {
	fixture := testfixture.New(t)
	genesis := testfixture.Genesis(t)
	update := fixture.Update(t, testfixture.Config(t, genesis))
	block := pq40eSignedConfigBlock(t, fixture, genesis, fixture.Envelope(t, update), 1)
	block.Metadata.Metadata[cb.BlockMetadataIndex_TRANSACTIONS_FILTER] = []byte{byte(pb.TxValidationCode_VALID)}
	exportRoot := t.TempDir()
	exporter, err := constructLedgerMgrWithTestDefaults(exportRoot)
	require.NoError(t, err)
	closeExporter := sync.OnceFunc(exporter.Close)
	t.Cleanup(closeExporter)
	source, err := exporter.CreateLedger(testfixture.ChannelID, genesis)
	require.NoError(t, err)
	require.NoError(t, source.CommitLegacy(&ledger.BlockAndPvtData{Block: block}, &ledger.CommitOptions{}))
	require.NoError(t, source.SubmitSnapshotRequest(1))
	snapshot := kvledger.SnapshotDirForLedgerBlockNum(filepath.Join(exportRoot, "snapshots"), testfixture.ChannelID, 1)
	require.Eventually(t, func() bool {
		pending, err := source.PendingSnapshotRequests()
		return err == nil && len(pending) == 0
	}, 10*time.Second, 20*time.Millisecond)
	signable, err := os.ReadFile(filepath.Join(snapshot, kvledger.SnapshotSignableMetadataFileName))
	require.NoError(t, err)
	additional, err := os.ReadFile(filepath.Join(snapshot, kvledger.SnapshotAdditionalMetadataFileName))
	require.NoError(t, err)
	closeExporter()

	root, state := t.TempDir(), t.TempDir()
	store, err := activation.OpenStore(state, nil)
	require.NoError(t, err)
	fixture.Provision(t, store, update.GetConfig())
	key := fixture.Channel(store, activation.Ledger{}).Signer.Bytes()
	keyFile := filepath.Join(state, "policy-key")
	require.NoError(t, os.WriteFile(keyFile, key, 0o600))
	channelDigest := sha256.Sum256([]byte(testfixture.ChannelID))
	genesisName := filepath.Join(state, fmt.Sprintf("genesis-%x", channelDigest))
	genesisHash, err := json.Marshal(hex.EncodeToString(protoutil.BlockHeaderHash(genesis.GetHeader())))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(genesisName, genesisHash, 0o600))
	require.NoError(t, os.WriteFile(genesisName+".block", protoutil.MarshalOrPanic(genesis), 0o600))
	joinName := filepath.Join(state, fmt.Sprintf("join-peer-%x", channelDigest))
	require.NoError(t, os.WriteFile(joinName+".block", protoutil.MarshalOrPanic(block), 0o600))
	manifest := &enrollment.Manifest{
		Mode: enrollment.Protected, Network: testfixture.Network, Node: testfixture.Node,
		Profile: pqtransport.ProfileV1, PolicySigner: keyFile, PolicySignerDigest: fmt.Sprintf("%x", sha256.Sum256(key)),
		StateDir: state, LedgerDir: filepath.Join(root, "ledgersData"),
	}
	registry, err := enrollment.OpenProtectedRegistry(manifest)
	require.NoError(t, err)
	verified, err := provisioning.VerifyJoinHistory(
		registry, testfixture.ChannelID, []*cb.Block{genesis, block}, block.GetHeader().GetNumber(), fixture.Crypto,
	)
	require.NoError(t, err)
	seed := sha256.Sum256([]byte("PQ4.0C activation fixture operator"))
	signer, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), seed[:])
	require.NoError(t, err)
	signed, err := provisioning.SignVerifiedPeerSnapshotAnchor(verified, signable, additional, signer)
	require.NoError(t, err)
	startPeer := func() (*Peer, func()) {
		p, closeLedger := newTestPeer(t, root)
		registry, err := enrollment.OpenProtectedRegistry(manifest)
		require.NoError(t, err)
		p.ProtectedRegistry = registry
		p.Initialize(nil, nil, nil, nil, nil, nil, 1)
		closePeer := sync.OnceFunc(func() {
			p.GossipService.Stop()
			p.StoreProvider.Close()
			closeLedger()
		})
		t.Cleanup(closePeer)
		return p, closePeer
	}
	p, closePeer := startPeer()
	require.ErrorContains(t, p.CreateChannelFromSnapshot(snapshot, nil, nil, nil), "read join-peer anchor")
	anchor := enrollment.PeerSnapshotAnchor{
		JoinAnchor:             fixture.JoinAnchor(t, genesis, block),
		SignableMetadataHash:   fmt.Sprintf("%x", sha256.Sum256(signable)),
		AdditionalMetadataHash: fmt.Sprintf("%x", sha256.Sum256(additional)),
	}
	downgrade := anchor
	downgrade.Profile = "baseline"
	require.NoError(t, os.WriteFile(joinName, fixture.SignedJoinAnchor(t, enrollment.PeerSnapshotAnchorDomain, downgrade), 0o600))
	require.ErrorContains(t, p.CreateChannelFromSnapshot(snapshot, nil, nil, nil), "node policy")
	require.NoError(t, os.WriteFile(joinName, signed, 0o600))
	metadataPath := filepath.Join(snapshot, kvledger.SnapshotAdditionalMetadataFileName)
	require.NoError(t, os.Chmod(metadataPath, 0o600))
	require.NoError(t, os.WriteFile(metadataPath, append(append([]byte(nil), additional...), '\n'), 0o600))
	require.ErrorContains(t, p.CreateChannelFromSnapshot(snapshot, nil, nil, nil), "conflicts with signed peer join anchor")
	ids, err := p.LedgerMgr.GetLedgerIDs()
	require.NoError(t, err)
	require.Empty(t, ids)
	require.NoError(t, os.WriteFile(metadataPath, additional, 0o600))
	require.NoError(t, p.CreateChannelFromSnapshot(snapshot, nil, nil, nil))
	require.Eventually(t, func() bool {
		channel := p.Channel(testfixture.ChannelID)
		return channel != nil && channel.activation.Ready() && !p.JoinBySnapshotStatus().GetInProgress()
	}, 10*time.Second, 20*time.Millisecond)
	require.EqualValues(t, 1, p.Channel(testfixture.ChannelID).Sequence())
	closePeer()

	require.NoError(t, os.Remove(joinName))
	closed, closeClosed := startPeer()
	require.Nil(t, closed.Channel(testfixture.ChannelID), "missing persisted provenance must keep the channel closed")
	closeClosed()
	require.NoError(t, os.WriteFile(joinName, signed, 0o600))
	restored, _ := startPeer()
	require.NotNil(t, restored.Channel(testfixture.ChannelID))
	require.True(t, restored.Channel(testfixture.ChannelID).activation.Ready())
	require.EqualValues(t, 1, restored.Channel(testfixture.ChannelID).Sequence())
}

func pq40eSignedConfigBlock(t *testing.T, fixture testfixture.Fixture, previous *cb.Block, envelope *cb.Envelope, lastConfig uint64) *cb.Block {
	t.Helper()
	block := protoutil.NewBlock(previous.GetHeader().GetNumber()+1, protoutil.BlockHeaderHash(previous.GetHeader()))
	block.Data.Data = [][]byte{protoutil.MarshalOrPanic(envelope)}
	block.Header.DataHash = protoutil.ComputeBlockDataHash(block.GetData())
	protoutil.InitBlockMetadata(block)

	lastConfigBytes := protoutil.MarshalOrPanic(&cb.LastConfig{Index: lastConfig})
	ordererMetadata := protoutil.MarshalOrPanic(&cb.OrdererBlockMetadata{LastConfig: &cb.LastConfig{Index: lastConfig}})
	signatureHeader, err := protoutil.NewSignatureHeader(fixture.Fabric)
	require.NoError(t, err)
	signatureHeaderBytes := protoutil.MarshalOrPanic(signatureHeader)
	signature, err := fixture.Fabric.Sign(util.ConcatenateBytes(
		ordererMetadata, signatureHeaderBytes, protoutil.BlockHeaderBytes(block.GetHeader()),
	))
	require.NoError(t, err)
	block.Metadata.Metadata[cb.BlockMetadataIndex_SIGNATURES] = protoutil.MarshalOrPanic(&cb.Metadata{
		Value: ordererMetadata,
		Signatures: []*cb.MetadataSignature{{
			SignatureHeader: signatureHeaderBytes,
			Signature:       signature,
		}},
	})
	block.Metadata.Metadata[cb.BlockMetadataIndex_LAST_CONFIG] = protoutil.MarshalOrPanic(&cb.Metadata{Value: lastConfigBytes})
	return block
}
