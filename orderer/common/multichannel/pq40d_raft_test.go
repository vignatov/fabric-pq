//go:build linux

// SPDX-License-Identifier: Apache-2.0

package multichannel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"code.cloudfoundry.org/clock"
	"github.com/hyperledger/fabric-lib-go/common/flogging"
	"github.com/hyperledger/fabric-lib-go/common/metrics/disabled"
	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	ab "github.com/hyperledger/fabric-protos-go-apiv2/orderer"
	pb "github.com/hyperledger/fabric-protos-go-apiv2/orderer/etcdraft"
	"github.com/hyperledger/fabric/common/channelconfig"
	configtxtest "github.com/hyperledger/fabric/common/configtx/test"
	"github.com/hyperledger/fabric/common/ledger/blockledger"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation/testfixture"
	"github.com/hyperledger/fabric/orderer/common/blockcutter"
	"github.com/hyperledger/fabric/orderer/common/cluster"
	"github.com/hyperledger/fabric/orderer/common/types"
	"github.com/hyperledger/fabric/orderer/consensus/etcdraft"
	raftmocks "github.com/hyperledger/fabric/orderer/consensus/etcdraft/mocks"
	"github.com/hyperledger/fabric/protoutil"
	"github.com/stretchr/testify/require"
	"go.etcd.io/etcd/server/v3/storage/wal"
	"go.etcd.io/raft/v3"
	"go.etcd.io/raft/v3/raftpb"
	"google.golang.org/protobuf/proto"
)

const pq40dCrash = 79

type pq40dConfigurator struct{}

func (pq40dConfigurator) Configure(string, []cluster.RemoteNode) {}

type pq40dSupport struct {
	*ChainSupport
	beforeApply func()
}

func (s pq40dSupport) WaitForBlockCommit() uint64 {
	number := s.ChainSupport.WaitForBlockCommit()
	s.beforeApply()
	return number
}

func TestPQ40DRaftProcessRecovery(t *testing.T) {
	for _, tc := range []struct {
		name       string
		breakpoint string
		approved   bool
	}{
		{name: "committed_without_approval", breakpoint: "before-guard"},
		{name: "approved_before_apply", breakpoint: "before-ledger-commit", approved: true},
		{name: "approved_after_append", breakpoint: "after-ledger-commit", approved: true},
		{name: "snapshot_committed_before_catchup", breakpoint: "snapshot-before-apply", approved: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			pq40dProvision(t, root, tc.approved)
			run := func(mode string) ([]byte, error) {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPQ40DRaftWorker$", "-test.v")
				cmd.Env = append(os.Environ(), "PQ40D_TEST_ROOT="+root, "PQ40D_TEST_MODE="+mode)
				return cmd.CombinedOutput()
			}

			out, err := run(tc.breakpoint)
			var exit *exec.ExitError
			require.ErrorAs(t, err, &exit, "%s", out)
			require.Equal(t, pq40dCrash, exit.ExitCode(), "%s", out)
			require.True(t, wal.Exist(filepath.Join(root, "wal")))
			mode := "verify-quarantine"
			if tc.approved {
				mode = "verify-approval"
			}
			if tc.breakpoint == "snapshot-before-apply" {
				files, err := filepath.Glob(filepath.Join(root, "snap", "*.snap"))
				require.NoError(t, err)
				require.NotEmpty(t, files)
				mode = "verify-approval-snapshot"
			}
			for range 2 {
				out, err := run(mode)
				require.NoError(t, err, "%s", out)
			}
		})
	}
}

func pq40dProvision(t *testing.T, root string, approved bool) {
	t.Helper()
	genesis := pq40dGenesis(t, 1)
	pq40dProvisionGenesis(t, root, genesis, approved)
}

func pq40dGenesis(t *testing.T, nodes int) *cb.Block {
	t.Helper()
	return pq40dGenesisForChannel(t, testfixture.ChannelID, nodes)
}

func pq40dGenesisForChannel(t *testing.T, channelID string, nodes int) *cb.Block {
	t.Helper()
	fixture := testfixture.New(t)
	genesis, err := configtxtest.MakeGenesisBlock(channelID)
	require.NoError(t, err)
	envelope, err := protoutil.ExtractEnvelope(genesis, 0)
	require.NoError(t, err)
	config := &cb.ConfigEnvelope{}
	_, err = protoutil.UnmarshalEnvelopeOfType(envelope, cb.HeaderType_CONFIG, config)
	require.NoError(t, err)
	metadata := &pb.ConfigMetadata{
		Options: &pb.Options{TickInterval: "10ms", HeartbeatTick: 1, ElectionTick: 5, MaxInflightBlocks: 4},
	}
	for i := range nodes {
		cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{byte(i + 1)}})
		metadata.Consenters = append(metadata.Consenters, &pb.Consenter{Host: "localhost", Port: uint32(7050 + i), ClientTlsCert: cert, ServerTlsCert: cert})
	}
	consensusType := config.GetConfig().GetChannelGroup().GetGroups()["Orderer"].GetValues()["ConsensusType"]
	consensusType.Value = protoutil.MarshalOrPanic(&ab.ConsensusType{Type: "etcdraft", Metadata: protoutil.MarshalOrPanic(metadata)})
	signed, err := protoutil.CreateSignedEnvelope(cb.HeaderType_CONFIG, channelID, fixture.Fabric, config, 0, 0)
	require.NoError(t, err)
	genesis.Data.Data[0] = protoutil.MarshalOrPanic(signed)
	genesis.Header.DataHash = protoutil.ComputeBlockDataHash(genesis.GetData())
	return genesis
}

func pq40dProvisionGenesis(t *testing.T, root string, genesis *cb.Block, approved bool) {
	t.Helper()
	fixture := testfixture.New(t)
	factory := newFactory(filepath.Join(root, "ledger"))
	lgr, err := factory.GetOrCreate(testfixture.ChannelID)
	require.NoError(t, err)
	require.NoError(t, lgr.Append(genesis))
	factory.Close()

	store, err := activation.OpenStore(root, nil)
	require.NoError(t, err)
	base := testfixture.Config(t, genesis)
	fixture.Provision(t, store, base)
	id := sha256.Sum256([]byte(testfixture.ChannelID))
	hash, err := json.Marshal(hex.EncodeToString(protoutil.BlockHeaderHash(genesis.GetHeader())))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(root, fmt.Sprintf("genesis-%x", id)), hash, 0o600))
	update := fixture.Update(t, base)
	candidate := protoutil.NewBlock(1, protoutil.BlockHeaderHash(genesis.GetHeader()))
	candidate.Data = &cb.BlockData{Data: [][]byte{protoutil.MarshalOrPanic(fixture.Envelope(t, update))}}
	candidate.Header.DataHash = protoutil.ComputeBlockDataHash(candidate.GetData())
	require.NoError(t, os.WriteFile(filepath.Join(root, "candidate"), protoutil.MarshalOrPanic(candidate), 0o600))
	if approved {
		auth, err := json.Marshal(fixture.Authorize(t, 1, base, update.GetConfig()))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(root, fmt.Sprintf("approval-%x-2", id)), auth, 0o600))
	}
}

func TestPQ40DRaftWorker(t *testing.T) {
	root, mode := os.Getenv("PQ40D_TEST_ROOT"), os.Getenv("PQ40D_TEST_MODE")
	if root == "" {
		t.Skip("spawned by TestPQ40DRaftProcessRecovery")
	}
	var armed atomic.Bool
	crash := func(boundary string) {
		if (mode == boundary || mode == "snapshot-before-apply" && boundary == "before-ledger-commit") && armed.Load() {
			os.Exit(pq40dCrash)
		}
	}
	raw, err := os.ReadFile(filepath.Join(root, "candidate"))
	require.NoError(t, err)
	candidate, err := protoutil.UnmarshalBlock(raw)
	require.NoError(t, err)
	var puller etcdraft.CreateBlockPuller
	if strings.Contains(mode, "snapshot") {
		factory := newFactory(filepath.Join(root, "ledger"))
		ledger, err := factory.GetOrCreate(testfixture.ChannelID)
		require.NoError(t, err)
		genesis := blockledger.GetBlock(ledger, 0)
		require.NotNil(t, genesis)
		factory.Close()
		puller = pq40dSnapshotProof(t, genesis, proto.CloneOf(candidate), 8)
	}
	native, controller, ledger, support, err := pq40dNode(t, root, 1, nil, puller, crash)
	genesis, getErr := controller.Ledger.Block(0)
	require.NoError(t, getErr)

	if mode == "verify-quarantine" && err != nil {
		require.ErrorContains(t, err, "quarantined")
		require.Equal(t, uint64(1), ledger.Height())
		return
	}
	require.NoError(t, err)
	require.False(t, controller.Ready())
	native.Start()
	t.Cleanup(native.Halt)
	switch mode {
	case "verify-quarantine":
		require.Eventually(t, func() bool {
			_, status := native.StatusReport()
			return status == types.StatusFailed
		}, 10*time.Second, 10*time.Millisecond)
		require.False(t, controller.Ready())
		require.Equal(t, uint64(1), ledger.Height())
	case "verify-approval", "verify-approval-snapshot":
		require.Eventually(t, controller.Ready, 10*time.Second, 10*time.Millisecond)
		require.Equal(t, uint64(2), ledger.Height())
		block, err := controller.Ledger.Block(1)
		require.NoError(t, err)
		require.True(t, proto.Equal(candidate.GetHeader(), block.GetHeader()))
		oldBundle, err := support.CreateBundle(testfixture.ChannelID, testfixture.Config(t, genesis))
		require.NoError(t, err)
		actual, err := protoutil.GetConsenterMetadataFromBlock(block)
		require.NoError(t, err)
		verifyActivationMetadata(t, block, oldBundle, actual.GetValue())
	default:
		require.Eventually(t, controller.Ready, 10*time.Second, 10*time.Millisecond)
		envelope, err := protoutil.ExtractEnvelope(candidate, 0)
		require.NoError(t, err)
		armed.Store(true)
		switch mode {
		case "before-guard":
			require.ErrorContains(t, native.Configure(envelope, 0), "load operator approval")
			// Bypass the proposal guard to exercise receipt of a configuration
			// already decided before the local orderer can authorize it.
			require.NoError(t, native.Node.Propose(t.Context(), raw))
		case "snapshot-before-apply":
			message := pq40dSnapshotMessage(native.Node.Status(), raw, 8)
			require.NoError(t, native.Consensus(&ab.ConsensusRequest{Payload: protoutil.MarshalOrPanic(message)}, 2))
		default:
			require.NoError(t, native.Configure(envelope, 0))
		}
		<-time.After(10 * time.Second)
		t.Fatal("subprocess did not reach interruption point")
	}
}

func pq40dNode(t *testing.T, root string, raftID uint64, rpc etcdraft.RPC, puller etcdraft.CreateBlockPuller, probe func(string)) (*etcdraft.Chain, *activation.Channel, blockledger.ReadWriter, *ChainSupport, error) {
	t.Helper()
	fixture := testfixture.New(t)
	ledger, view := ordererActivationLedger(t, filepath.Join(root, "ledger"), func(string) {})
	tip, err := view.Block(ledger.Height() - 1)
	require.NoError(t, err)
	config, err := view.LatestConfig()
	require.NoError(t, err)
	store, err := activation.OpenStore(root, probe)
	require.NoError(t, err)
	controller := fixture.Channel(store, view)
	writer, support := activationWriter(t, fixture, ledger, config)
	writer.lastBlock = tip
	support.BlockWriter = writer
	support.activation = &controller
	support.cutter = blockcutter.NewReceiverImpl(testfixture.ChannelID, support, blockcutter.NewMetrics(&disabled.Provider{}))
	opts := pq40dRaftOptions(t, root, support, tip, raftID)
	supported := pq40dSupport{support, func() {
		if probe != nil {
			probe("before-guard")
		}
	}}
	native, err := etcdraft.NewChain(supported, opts, pq40dConfigurator{}, rpc, fixture.Crypto, puller, nil, nil)
	return native, &controller, ledger, support, err
}

func pq40dRaftOptions(t *testing.T, root string, support *ChainSupport, tip *cb.Block, raftID uint64) etcdraft.Options {
	t.Helper()
	raftMeta, err := protoutil.GetConsenterMetadataFromBlock(tip)
	require.NoError(t, err)
	configuration := &pb.ConfigMetadata{}
	require.NoError(t, proto.Unmarshal(support.SharedConfig().ConsensusMetadata(), configuration))
	meta, err := etcdraft.ReadBlockMetadata(raftMeta, configuration)
	require.NoError(t, err)
	return etcdraft.Options{
		RaftID: raftID, WALDir: filepath.Join(root, "wal"), SnapDir: filepath.Join(root, "snap"),
		Clock: clock.NewClock(), MemoryStorage: raft.NewMemoryStorage(),
		Logger: flogging.MustGetLogger("pq40d.test"), Metrics: etcdraft.NewMetrics(&disabled.Provider{}),
		TickInterval: 10 * time.Millisecond, ElectionTick: 10, HeartbeatTick: 1,
		MaxSizePerMsg: 1 << 20, MaxInflightBlocks: 4, EvictionSuspicion: time.Hour,
		BlockMetadata: meta, Consenters: etcdraft.CreateConsentersMap(meta, configuration),
	}
}

type pq40dTransport struct {
	id    uint64
	nodes map[uint64]*etcdraft.Chain
}

func (p pq40dTransport) SendConsensus(destination uint64, message *ab.ConsensusRequest) error {
	return p.nodes[destination].Consensus(message, p.id)
}

func (p pq40dTransport) SendSubmit(destination uint64, message *ab.SubmitRequest, report func(error)) error {
	report(p.nodes[destination].Submit(message, p.id))
	return nil
}

func TestPQ40DFollowerQuarantinePreservesQuorum(t *testing.T) {
	other, otherLedger := pq40dUnprotectedChain(t)
	genesis := pq40dGenesis(t, 3)
	nodes := map[uint64]*etcdraft.Chain{}
	roots := map[uint64]string{}
	ledgers := map[uint64]blockledger.ReadWriter{}
	for id := uint64(1); id <= 3; id++ {
		root := t.TempDir()
		roots[id] = root
		pq40dProvisionGenesis(t, root, proto.CloneOf(genesis), true)
		node, _, ledger, _, err := pq40dNode(t, root, id, pq40dTransport{id: id, nodes: nodes}, nil, nil)
		require.NoError(t, err)
		nodes[id] = node
		ledgers[id] = ledger
	}
	for _, node := range nodes {
		node.Start()
		t.Cleanup(node.Halt)
	}
	var leader uint64
	require.Eventually(t, func() bool {
		leader = 0
		for id, node := range nodes {
			relation, status := node.StatusReport()
			if relation != types.ConsensusRelationConsenter || status != types.StatusActive {
				return false
			}
			if node.Node.Status().RaftState == raft.StateLeader {
				leader = id
			}
		}
		return leader != 0
	}, 15*time.Second, 20*time.Millisecond)
	follower := leader%3 + 1
	channelHash := sha256.Sum256([]byte(testfixture.ChannelID))
	require.NoError(t, os.Remove(filepath.Join(roots[follower], fmt.Sprintf("approval-%x-2", channelHash))))
	raw, err := os.ReadFile(filepath.Join(roots[leader], "candidate"))
	require.NoError(t, err)
	candidate, err := protoutil.UnmarshalBlock(raw)
	require.NoError(t, err)
	config, err := protoutil.ExtractEnvelope(candidate, 0)
	require.NoError(t, err)
	require.NoError(t, nodes[leader].Configure(config, 0))
	require.Eventually(t, func() bool {
		_, status := nodes[follower].StatusReport()
		return status == types.StatusFailed
	}, 15*time.Second, 20*time.Millisecond)
	for id, ledger := range ledgers {
		if id == follower {
			require.Equal(t, uint64(1), ledger.Height())
			continue
		}
		require.Eventually(t, func() bool { return ledger.Height() == 2 }, 15*time.Second, 20*time.Millisecond)
	}
	envelope, err := protoutil.CreateSignedEnvelope(cb.HeaderType_MESSAGE, other.ChannelID(), testfixture.New(t).Fabric, &cb.Config{}, 0, 0)
	require.NoError(t, err)
	require.NoError(t, other.WaitReady())
	require.NoError(t, other.Order(envelope, 0))
	require.Eventually(t, func() bool { return otherLedger.Height() == 2 }, 10*time.Second, 20*time.Millisecond)
}

func pq40dUnprotectedChain(t *testing.T) (*ChainSupport, blockledger.ReadWriter) {
	t.Helper()
	const channelID = "independent-channel"
	root := t.TempDir()
	factory := newFactory(filepath.Join(root, "ledger"))
	t.Cleanup(factory.Close)
	ledger, err := factory.GetOrCreate(channelID)
	require.NoError(t, err)
	genesis := pq40dGenesisForChannel(t, channelID, 1)
	require.NoError(t, ledger.Append(genesis))
	fixture := testfixture.New(t)
	bundle, err := channelconfig.NewBundle(channelID, testfixture.Config(t, genesis), fixture.Crypto)
	require.NoError(t, err)
	support := &ChainSupport{
		SignerSerializer: fixture.Fabric,
		ledgerResources: &ledgerResources{
			ReadWriter: ledger,
			configResources: &configResources{
				mutableResources: channelconfig.NewBundleSource(bundle),
				bccsp:            fixture.Crypto,
				signer:           fixture.Fabric,
			},
		},
	}
	support.BlockWriter = newBlockWriter(genesis, support)
	support.cutter = blockcutter.NewReceiverImpl(channelID, support, blockcutter.NewMetrics(&disabled.Provider{}))
	opts := pq40dRaftOptions(t, root, support, genesis, 1)
	native, err := etcdraft.NewChain(support, opts, pq40dConfigurator{}, nil, fixture.Crypto, nil, nil, nil)
	require.NoError(t, err)
	support.Chain = native
	native.Start()
	t.Cleanup(native.Halt)
	require.Eventually(t, func() bool { return native.Node.Status().RaftState == raft.StateLeader }, 10*time.Second, 20*time.Millisecond)
	return support, ledger
}

type pq40dSnapshotPuller struct {
	etcdraft.BlockPuller
	block *cb.Block
}

func (p pq40dSnapshotPuller) PullBlock(uint64) *cb.Block { return p.block }
func (p pq40dSnapshotPuller) Close()                     {}

func TestPQ40DSnapshotCannotBypassLocalApproval(t *testing.T) {
	root := t.TempDir()
	genesis := pq40dGenesis(t, 1)
	pq40dProvisionGenesis(t, root, genesis, false)
	raw, err := os.ReadFile(filepath.Join(root, "candidate"))
	require.NoError(t, err)
	proposed, err := protoutil.UnmarshalBlock(raw)
	require.NoError(t, err)
	const index = 8
	puller := pq40dSnapshotProof(t, genesis, proposed, index)
	native, controller, ledger, _, err := pq40dNode(t, root, 1, nil, puller, nil)
	require.NoError(t, err)
	native.Start()
	t.Cleanup(native.Halt)
	require.Eventually(t, controller.Ready, 10*time.Second, 10*time.Millisecond)
	message := pq40dSnapshotMessage(native.Node.Status(), raw, index)
	require.ErrorContains(t, native.Consensus(&ab.ConsensusRequest{Payload: protoutil.MarshalOrPanic(message)}, 2), "load catch-up operator approval")
	require.False(t, controller.Ready())
	require.Equal(t, uint64(1), ledger.Height())
	_, statusAfter := native.StatusReport()
	require.Equal(t, types.StatusFailed, statusAfter)
}

func TestPQ40DNativeSnapshotMembershipBoundary(t *testing.T) {
	const index = 8
	for _, tc := range []struct {
		name          string
		blockIndex    uint64
		voters        []uint64
		boundaryError string
	}{
		{name: "mismatched voters", blockIndex: index, voters: []uint64{1, 2}, boundaryError: "snapshot voters conflict"},
		{name: "missing membership", voters: []uint64{1}, boundaryError: "missing signed Fabric membership"},
		{name: "mismatched index", blockIndex: index - 1, voters: []uint64{1}, boundaryError: "missing signed Fabric membership"},
		{name: "verified snapshot", blockIndex: index, voters: []uint64{1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			genesis := pq40dGenesis(t, 1)
			pq40dProvisionGenesis(t, root, genesis, true)
			raw, err := os.ReadFile(filepath.Join(root, "candidate"))
			require.NoError(t, err)
			candidate, err := protoutil.UnmarshalBlock(raw)
			require.NoError(t, err)
			initialEvidence := pq40dSnapshotProof(t, genesis, proto.CloneOf(candidate), tc.blockIndex)
			verifiedEvidence := pq40dSnapshotProof(t, genesis, proto.CloneOf(candidate), index)
			var verified atomic.Bool
			puller := func() (etcdraft.BlockPuller, error) {
				if verified.Load() {
					return verifiedEvidence()
				}
				return initialEvidence()
			}
			native, controller, ledger, _, err := pq40dNode(t, root, 1, &raftmocks.FakeRPC{}, puller, nil)
			require.NoError(t, err)
			native.Start()
			t.Cleanup(native.Halt)
			require.Eventually(t, controller.Ready, 10*time.Second, 20*time.Millisecond)

			send := func(voters []uint64) error {
				message := pq40dSnapshotMessage(native.Node.Status(), raw, index)
				message.Snapshot.Metadata.ConfState.Voters = voters
				return native.Consensus(&ab.ConsensusRequest{Payload: protoutil.MarshalOrPanic(message)}, 2)
			}
			if tc.boundaryError != "" {
				err := send(tc.voters)
				require.ErrorContains(t, err, "protected snapshot evidence is incomplete")
				require.ErrorContains(t, err, tc.boundaryError)
				require.False(t, controller.Ready())
				require.Error(t, native.WaitReady())
				require.Equal(t, uint64(1), ledger.Height())
				state := native.Node.Status()
				require.Less(t, state.GetCommit(), uint64(index))
				require.Equal(t, map[uint64]struct{}{1: {}}, state.Config.Voters.IDs())
				_, status := native.StatusReport()
				require.Equal(t, types.StatusOnBoarding, status)

				verified.Store(true)
			}
			require.NoError(t, send([]uint64{1}))
			require.Eventually(t, func() bool {
				return controller.Ready() && native.Node.Status().Applied >= index
			}, 10*time.Second, 20*time.Millisecond)
			require.NoError(t, native.WaitReady())
			require.Equal(t, uint64(2), ledger.Height())
			block, err := ledger.RetrieveBlockByNumber(1)
			require.NoError(t, err)
			require.True(t, proto.Equal(candidate.GetHeader(), block.GetHeader()))
			require.Equal(t, uint64(index), pq40dPromotionBlockIndex(t, block))
		})
	}
}

func pq40dSnapshotProof(t *testing.T, genesis, candidate *cb.Block, index uint64) etcdraft.CreateBlockPuller {
	t.Helper()
	source, _ := ordererActivationLedger(t, t.TempDir(), func(string) {})
	require.NoError(t, source.Append(genesis))
	writer, _ := activationWriter(t, testfixture.New(t), source, genesis)
	var metadata []byte
	if index != 0 {
		metadata = protoutil.MarshalOrPanic(&pb.BlockMetadata{RaftIndex: index, ConsenterIds: []uint64{1}, NextConsenterId: 2})
	}
	writer.WriteConfigBlock(candidate, metadata)
	return func() (etcdraft.BlockPuller, error) {
		return pq40dSnapshotPuller{block: proto.CloneOf(candidate)}, nil
	}
}

func pq40dSnapshotMessage(status raft.Status, raw []byte, index uint64) *raftpb.Message {
	return &raftpb.Message{
		From: new(uint64(2)), To: new(uint64(1)), Term: new(status.GetTerm() + 1),
		Type: new(raftpb.MsgSnap),
		Snapshot: &raftpb.Snapshot{
			Data: raw,
			Metadata: &raftpb.SnapshotMetadata{
				Index: &index, Term: new(status.GetTerm()),
				ConfState: &raftpb.ConfState{Voters: []uint64{1}},
			},
		},
	}
}
