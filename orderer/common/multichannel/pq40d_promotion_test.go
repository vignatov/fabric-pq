//go:build linux

// SPDX-License-Identifier: Apache-2.0

package multichannel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hyperledger/fabric-lib-go/common/flogging"
	"github.com/hyperledger/fabric-lib-go/common/metrics/disabled"
	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	mb "github.com/hyperledger/fabric-protos-go-apiv2/msp"
	ab "github.com/hyperledger/fabric-protos-go-apiv2/orderer"
	pb "github.com/hyperledger/fabric-protos-go-apiv2/orderer/etcdraft"
	"github.com/hyperledger/fabric/common/channelconfig"
	"github.com/hyperledger/fabric/common/crypto/tlsgen"
	"github.com/hyperledger/fabric/common/ledger/blockledger"
	"github.com/hyperledger/fabric/internal/pkg/comm"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation/testfixture"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/enrollment"
	"github.com/hyperledger/fabric/orderer/common/cluster"
	"github.com/hyperledger/fabric/orderer/common/localconfig"
	"github.com/hyperledger/fabric/orderer/common/types"
	"github.com/hyperledger/fabric/orderer/consensus"
	"github.com/hyperledger/fabric/orderer/consensus/etcdraft"
	"github.com/hyperledger/fabric/protoutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.etcd.io/raft/v3"
	"google.golang.org/protobuf/proto"
)

const promotionRaftID = 4

func TestPQ40DProtectedParticipationPromotion(t *testing.T) {
	testProtectedParticipationPromotion(t, false)
}

func TestPQ40EManagedOrdererNonGenesisPromotion(t *testing.T) {
	testProtectedParticipationPromotion(t, true)
}

func testProtectedParticipationPromotion(t *testing.T, managed bool) {
	t.Helper()
	fixture := testfixture.New(t)
	ca, err := tlsgen.NewCA()
	require.NoError(t, err)
	deliverKey, err := ca.NewServerCertKeyPair("127.0.0.1")
	require.NoError(t, err)
	server, err := comm.NewGRPCServer("127.0.0.1:0", comm.ServerConfig{
		SecOpts: comm.SecureOptions{UseTLS: true, Certificate: deliverKey.Cert, Key: deliverKey.Key},
	})
	require.NoError(t, err)
	t.Cleanup(server.Stop)

	members := make([]*pb.Consenter, promotionRaftID)
	var promotedClient *tlsgen.CertKeyPair
	for i := range members {
		serverKey, err := ca.NewServerCertKeyPair("127.0.0.1")
		require.NoError(t, err)
		clientKey, err := ca.NewClientCertKeyPair()
		require.NoError(t, err)
		promotedClient = clientKey
		members[i] = &pb.Consenter{
			Host: "127.0.0.1", Port: uint32(7050 + i),
			ServerTlsCert: serverKey.Cert, ClientTlsCert: clientKey.Cert,
		}
	}
	genesis, base, raftConfig := pq40dPromotionGenesis(t, fixture, server.Address(), ca.CertBytes(), members[:promotionRaftID-1])
	next := proto.CloneOf(base)
	raftConfig.Consenters = members
	pq40dSetRaftConfig(next, raftConfig)
	membership := fixture.UpdateTo(t, base, next)
	pending := fixture.Update(t, membership.GetConfig())

	transport := &pq40dPromotionNetwork{}
	sourceLedgers := map[uint64]blockledger.ReadWriter{}
	for id := uint64(1); id < promotionRaftID; id++ {
		root := t.TempDir()
		pq40dProvisionGenesis(t, root, genesis, false)
		pq40dStagePromotion(t, root, fixture, base, membership.GetConfig(), pending.GetConfig())
		node, _, ledger, _, err := pq40dNode(t, root, id, pq40dPromotionRPC{network: transport, id: id}, nil, nil)
		require.NoError(t, err)
		transport.nodes.Store(id, node)
		sourceLedgers[id] = ledger
		node.Start()
		t.Cleanup(node.Halt)
	}
	join := transport.commitConfig(t, sourceLedgers, fixture.Envelope(t, membership), 0, 1)
	joinIndex := pq40dPromotionBlockIndex(t, join)
	require.NotZero(t, joinIndex)
	replayBlock := transport.commitConfig(t, sourceLedgers, fixture.Envelope(t, pending), 1, 2)
	replayIndex := pq40dPromotionBlockIndex(t, replayBlock)
	require.Greater(t, replayIndex, joinIndex)

	// Participation receives only the anchored genesis and the membership
	// block. The committed update at height 3 must arrive through native Raft.
	ab.RegisterAtomicBroadcastServer(server.Server(), &pq40dPromotionDeliver{blocks: []*cb.Block{genesis, join}})
	go server.Start()

	root := t.TempDir()
	store, err := activation.OpenStore(root, nil)
	require.NoError(t, err)
	fixture.Provision(t, store, base)
	anchor := filepath.Join(root, "policy-key")
	controller := fixture.Channel(store, activation.Ledger{})
	require.NoError(t, os.WriteFile(anchor, controller.Signer.Bytes(), 0o600))
	channelHash := sha256.Sum256([]byte(testfixture.ChannelID))
	genesisPath := filepath.Join(root, fmt.Sprintf("genesis-%x", channelHash))
	hash, err := json.Marshal(hex.EncodeToString(protoutil.BlockHeaderHash(genesis.GetHeader())))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(genesisPath, hash, 0o600))
	require.NoError(t, os.WriteFile(genesisPath+".block", protoutil.MarshalOrPanic(genesis), 0o600))
	pq40dStagePromotion(t, root, fixture, base, membership.GetConfig(), pending.GetConfig())

	factory := &pq40dPromotionFactory{
		Factory: newFactory(filepath.Join(root, "ledger")), arrived: make(chan struct{}), resume: make(chan struct{}),
	}
	t.Cleanup(factory.Close)
	var release sync.Once
	resume := func() { release.Do(func() { close(factory.resume) }) }
	var published atomic.Uint64
	config := localconfig.TopLevel{
		General: localconfig.General{
			PQActivation: localconfig.PQActivation{
				Channels: []string{testfixture.ChannelID}, StateDir: root, TrustAnchor: anchor,
				Network: testfixture.Network, Node: testfixture.Node,
			},
			Cluster: localconfig.Cluster{
				ReplicationBufferSize: 1 << 20, ReplicationPullTimeout: 2 * time.Second,
				ReplicationRetryTimeout: 20 * time.Millisecond, ReplicationMaxRetries: 5,
			},
		},
		FileLedger: localconfig.FileLedger{Location: filepath.Join(root, "ledger")},
	}
	dialer := &cluster.PredicateDialer{Config: comm.ClientConfig{
		DialTimeout: 2 * time.Second,
		SecOpts: comm.SecureOptions{
			UseTLS: true, RequireClientCert: true, Certificate: promotedClient.Cert, Key: promotedClient.Key,
		},
	}}
	publish := func(bundle *channelconfig.Bundle) {
		published.Store(bundle.ConfigtxValidator().Sequence())
	}
	var registrar *Registrar
	if managed {
		key := controller.Signer.Bytes()
		registry, err := enrollment.OpenProtectedRegistry(&enrollment.Manifest{
			Mode: enrollment.Protected, Network: testfixture.Network, Node: testfixture.Node, Profile: pqtransport.ProfileV1,
			StateDir: root, LedgerDir: config.FileLedger.Location, PolicySigner: anchor,
			PolicySignerDigest: fmt.Sprintf("%x", sha256.Sum256(key)),
		})
		require.NoError(t, err)
		config.General.PQActivation = localconfig.PQActivation{}
		registrar = NewManagedRegistrar(config, factory, fixture.Fabric, &disabled.Provider{}, fixture.Crypto, dialer, registry, nil, publish)
	} else {
		registrar = NewRegistrar(config, factory, fixture.Fabric, &disabled.Provider{}, fixture.Crypto, dialer, publish)
	}
	memberCheck := &etcdraft.Consenter{
		Cert: members[promotionRaftID-1].GetServerTlsCert(), BCCSP: fixture.Crypto,
		Logger: flogging.MustGetLogger("pq40d.promotion"),
	}
	registrar.Initialize(map[string]consensus.Consenter{
		"etcdraft": &pq40dPromotionConsenter{
			Consenter: memberCheck,
			build: func(support consensus.ConsenterSupport) (consensus.Chain, error) {
				cs := support.(*ChainSupport)
				opts := pq40dRaftOptions(t, root, cs, cs.Block(cs.Height()-1), promotionRaftID)
				return etcdraft.NewChain(cs, opts, pq40dConfigurator{}, pq40dPromotionRPC{network: transport, id: promotionRaftID}, fixture.Crypto, nil, nil, nil)
			},
		},
	})
	t.Cleanup(func() {
		resume()
		if follower := registrar.GetFollower(testfixture.ChannelID); follower != nil {
			follower.Halt()
		}
		if chain := registrar.GetChain(testfixture.ChannelID); chain != nil {
			chain.Halt()
		}
	})

	if managed {
		joinAnchor := fixture.JoinAnchor(t, genesis, join)
		joinPath := filepath.Join(root, fmt.Sprintf("join-orderer-%x", channelHash))
		_, err := registrar.JoinChannel(testfixture.ChannelID, join)
		require.ErrorContains(t, err, "read join-orderer anchor")
		require.Empty(t, factory.ChannelIDs(), "unauthenticated join must not create a ledger")
		conflict := joinAnchor
		conflict.GenesisHash = fmt.Sprintf("%064x", 1)
		require.NoError(t, os.WriteFile(joinPath, fixture.SignedJoinAnchor(t, enrollment.OrdererJoinAnchorDomain, conflict), 0o600))
		_, err = registrar.JoinChannel(testfixture.ChannelID, join)
		require.ErrorContains(t, err, "conflicts with genesis")
		require.Empty(t, factory.ChannelIDs())
		require.NoError(t, os.WriteFile(joinPath, fixture.SignedJoinAnchor(t, enrollment.OrdererJoinAnchorDomain, joinAnchor), 0o600))
	}
	info, err := registrar.JoinChannel(testfixture.ChannelID, join)
	require.NoError(t, err)
	require.Equal(t, types.ConsensusRelationFollower, info.ConsensusRelation)
	require.Equal(t, types.StatusOnBoarding, info.Status)
	var promoted *ChainSupport
	require.Eventually(t, func() bool {
		promoted = registrar.GetChain(testfixture.ChannelID)
		return promoted != nil
	}, 15*time.Second, 20*time.Millisecond)
	require.Nil(t, registrar.GetFollower(testfixture.ChannelID))
	require.Equal(t, uint64(2), promoted.Height())
	gotJoin, err := promoted.RetrieveBlockByNumber(1)
	require.NoError(t, err)
	require.True(t, proto.Equal(join, gotJoin))
	normal, err := protoutil.CreateSignedEnvelope(cb.HeaderType_MESSAGE, testfixture.ChannelID, fixture.Fabric, &cb.Config{}, 0, 0)
	require.NoError(t, err)
	assertClosed := func() {
		t.Helper()
		require.False(t, promoted.AdmissionReady())
		require.Error(t, promoted.WaitReady())
		_, _, _, err := registrar.BroadcastChannelSupport(normal)
		require.ErrorContains(t, err, "admission is closed")
		require.Zero(t, published.Load())
		select {
		case <-promoted.RequiredDeliveryAdmission():
		default:
			t.Fatal("delivery admission is open during replay")
		}
		relation, status := promoted.StatusReport()
		require.Equal(t, types.ConsensusRelationConsenter, relation)
		require.Equal(t, types.StatusOnBoarding, status)
	}
	assertClosed()
	native := promoted.Chain.(*etcdraft.Chain)
	transport.nodes.Store(uint64(promotionRaftID), native)
	select {
	case <-factory.arrived:
	case <-time.After(15 * time.Second):
		t.Fatal("promoted node did not reach the committed configuration replay")
	}
	state := native.Node.Status()
	require.GreaterOrEqual(t, state.GetCommit(), replayIndex)
	require.Less(t, state.Applied, replayIndex)
	require.Equal(t, uint64(2), promoted.Height())
	assertClosed()

	resume()
	require.Eventually(t, func() bool {
		return promoted.AdmissionReady() && native.Node.Status().Applied >= replayIndex
	}, 15*time.Second, 20*time.Millisecond)
	require.NoError(t, promoted.WaitReady())
	_, _, ready, err := registrar.BroadcastChannelSupport(normal)
	require.NoError(t, err)
	require.Same(t, promoted, ready)
	select {
	case <-promoted.RequiredDeliveryAdmission():
		t.Fatal("delivery admission is closed after replay")
	default:
	}
	require.Equal(t, uint64(2), published.Load())
	require.Equal(t, uint64(3), promoted.Height())
	got, err := promoted.RetrieveBlockByNumber(2)
	require.NoError(t, err)
	require.True(t, proto.Equal(replayBlock.GetHeader(), got.GetHeader()))
}

func pq40dPromotionBlockIndex(t *testing.T, block *cb.Block) uint64 {
	t.Helper()
	metadata, err := protoutil.GetConsenterMetadataFromBlock(block)
	require.NoError(t, err)
	config := &pb.BlockMetadata{}
	require.NoError(t, proto.Unmarshal(metadata.GetValue(), config))
	return config.GetRaftIndex()
}

func pq40dPromotionGenesis(t *testing.T, fixture testfixture.Fixture, endpoint string, root []byte, members []*pb.Consenter) (*cb.Block, *cb.Config, *pb.ConfigMetadata) {
	t.Helper()
	genesis := testfixture.Genesis(t)
	config := testfixture.Config(t, genesis)
	var setTLSRoot func(*cb.ConfigGroup)
	setTLSRoot = func(group *cb.ConfigGroup) {
		if value := group.GetValues()["MSP"]; value != nil {
			wrapper := &mb.MSPConfig{}
			require.NoError(t, proto.Unmarshal(value.GetValue(), wrapper))
			msp := &mb.FabricMSPConfig{}
			require.NoError(t, proto.Unmarshal(wrapper.GetConfig(), msp))
			msp.TlsRootCerts = append(msp.GetTlsRootCerts(), root)
			wrapper.Config = protoutil.MarshalOrPanic(msp)
			value.Value = protoutil.MarshalOrPanic(wrapper)
		}
		for _, child := range group.GetGroups() {
			setTLSRoot(child)
		}
	}
	setTLSRoot(config.GetChannelGroup())
	org := config.GetChannelGroup().GetGroups()["Orderer"].GetGroups()["SampleOrg"]
	org.Values["Endpoints"] = &cb.ConfigValue{
		ModPolicy: "Admins", Value: protoutil.MarshalOrPanic(&cb.OrdererAddresses{Addresses: []string{endpoint}}),
	}
	metadata := &pb.ConfigMetadata{
		Consenters: members,
		Options:    &pb.Options{TickInterval: "10ms", HeartbeatTick: 1, ElectionTick: 10, MaxInflightBlocks: 4},
	}
	pq40dSetRaftConfig(config, metadata)
	genesis.Data.Data[0] = protoutil.MarshalOrPanic(fixture.Envelope(t, &cb.ConfigEnvelope{Config: config}))
	genesis.Header.DataHash = protoutil.ComputeBlockDataHash(genesis.GetData())
	return genesis, config, metadata
}

func pq40dSetRaftConfig(config *cb.Config, metadata *pb.ConfigMetadata) {
	value := config.GetChannelGroup().GetGroups()["Orderer"].GetValues()["ConsensusType"]
	value.Value = protoutil.MarshalOrPanic(&ab.ConsensusType{Type: "etcdraft", Metadata: protoutil.MarshalOrPanic(metadata)})
}

func pq40dStagePromotion(t *testing.T, root string, fixture testfixture.Fixture, configs ...*cb.Config) {
	t.Helper()
	channelHash := sha256.Sum256([]byte(testfixture.ChannelID))
	for i := 1; i < len(configs); i++ {
		approval, err := json.Marshal(fixture.Authorize(t, uint64(i), configs[i-1], configs[i]))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(root, fmt.Sprintf("approval-%x-%d", channelHash, i+1)), approval, 0o600))
	}
}

type pq40dPromotionNetwork struct {
	nodes sync.Map
}

func (n *pq40dPromotionNetwork) commitConfig(t *testing.T, ledgers map[uint64]blockledger.ReadWriter, envelope *cb.Envelope, sequence, blockNumber uint64) *cb.Block {
	t.Helper()
	var committed *cb.Block
	var proposedTerm uint64
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		for _, ledger := range ledgers {
			if ledger.Height() > blockNumber {
				block, err := ledger.RetrieveBlockByNumber(blockNumber)
				require.NoError(collect, err)
				committed = block
				return
			}
		}

		for id, ledger := range ledgers {
			node, _ := n.nodes.Load(id)
			chain := node.(*etcdraft.Chain)
			_, status := chain.StatusReport()
			if status != types.StatusActive || ledger.Height() != blockNumber {
				continue
			}
			state := chain.Node.Status()
			if state.RaftState != raft.StateLeader || state.GetTerm() <= proposedTerm {
				continue
			}
			// An accepted proposal can still be lost on a leadership change.
			// Retry it in a new term only while the block is absent.
			require.NoError(collect, chain.Configure(envelope, sequence))
			proposedTerm = state.GetTerm()
			break
		}
		collect.Errorf("waiting for committed configuration block %d", blockNumber)
	}, 15*time.Second, 20*time.Millisecond)
	return committed
}

type pq40dPromotionRPC struct {
	network *pq40dPromotionNetwork
	id      uint64
}

func (r pq40dPromotionRPC) SendConsensus(to uint64, request *ab.ConsensusRequest) error {
	node, present := r.network.nodes.Load(to)
	if !present {
		return errors.New("test replica is disconnected")
	}
	return node.(*etcdraft.Chain).Consensus(request, r.id)
}

func (r pq40dPromotionRPC) SendSubmit(to uint64, _ *ab.SubmitRequest, _ func(error)) error {
	// The test submits directly to the leader and reselects it on each retry.
	return fmt.Errorf("Raft leadership changed before node %d could submit to node %d", r.id, to)
}

type pq40dPromotionConsenter struct {
	*etcdraft.Consenter
	build func(consensus.ConsenterSupport) (consensus.Chain, error)
}

func (c *pq40dPromotionConsenter) HandleChain(support consensus.ConsenterSupport, _ *cb.Metadata) (consensus.Chain, error) {
	return c.build(support)
}

type pq40dPromotionDeliver struct {
	ab.UnimplementedAtomicBroadcastServer
	blocks []*cb.Block
}

func (d *pq40dPromotionDeliver) Deliver(stream ab.AtomicBroadcast_DeliverServer) error {
	envelope, err := stream.Recv()
	if err != nil {
		return err
	}
	seek := &ab.SeekInfo{}
	if _, err := protoutil.UnmarshalEnvelopeOfType(envelope, cb.HeaderType_DELIVER_SEEK_INFO, seek); err != nil {
		return err
	}
	start := seek.GetStart().GetSpecified().GetNumber()
	if seek.GetStart().GetNewest() != nil {
		start = uint64(len(d.blocks) - 1)
	}
	for _, block := range d.blocks[start:] {
		if err := stream.Send(&ab.DeliverResponse{Type: &ab.DeliverResponse_Block{Block: block}}); err != nil {
			return err
		}
	}
	return nil
}

type pq40dPromotionFactory struct {
	blockledger.Factory
	arrived chan struct{}
	resume  chan struct{}
}

func (f *pq40dPromotionFactory) GetOrCreate(channel string) (blockledger.ReadWriter, error) {
	readerWriter, err := f.Factory.GetOrCreate(channel)
	if err != nil {
		return nil, err
	}
	return &pq40dPromotionLedger{ReadWriter: readerWriter, factory: f}, nil
}

type pq40dPromotionLedger struct {
	blockledger.ReadWriter
	factory *pq40dPromotionFactory
}

func (l *pq40dPromotionLedger) Append(block *cb.Block) error {
	if block.GetHeader().GetNumber() == 2 {
		close(l.factory.arrived)
		<-l.factory.resume
	}
	return l.ReadWriter.Append(block)
}
