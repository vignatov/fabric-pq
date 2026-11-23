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
	"sync/atomic"
	"testing"
	"time"

	"code.cloudfoundry.org/clock"
	"github.com/hyperledger/fabric-lib-go/common/flogging"
	"github.com/hyperledger/fabric-lib-go/common/metrics/disabled"
	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	ab "github.com/hyperledger/fabric-protos-go-apiv2/orderer"
	pb "github.com/hyperledger/fabric-protos-go-apiv2/orderer/etcdraft"
	"github.com/hyperledger/fabric/common/ledger/blockledger"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation/testfixture"
	"github.com/hyperledger/fabric/orderer/common/blockcutter"
	"github.com/hyperledger/fabric/orderer/common/cluster"
	"github.com/hyperledger/fabric/orderer/common/types"
	"github.com/hyperledger/fabric/orderer/consensus/etcdraft"
	"github.com/hyperledger/fabric/protoutil"
	"github.com/stretchr/testify/require"
	"go.etcd.io/etcd/server/v3/storage/wal"
	"go.etcd.io/raft/v3"
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
	fixture := testfixture.New(t)
	genesis := testfixture.Genesis(t)
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
	genesis.Data.Data[0] = protoutil.MarshalOrPanic(fixture.Envelope(t, config))
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
		if mode == boundary && armed.Load() {
			os.Exit(pq40dCrash)
		}
	}
	native, controller, ledger, support, err := pq40dNode(t, root, 1, nil, crash)
	genesis, getErr := controller.Ledger.Block(0)
	require.NoError(t, getErr)
	raw, getErr := os.ReadFile(filepath.Join(root, "candidate"))
	require.NoError(t, getErr)
	candidate, getErr := protoutil.UnmarshalBlock(raw)
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
	case "verify-approval":
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
		if mode == "before-guard" {
			require.ErrorContains(t, native.Configure(envelope, 0), "load operator approval")
			// Bypass the proposal guard to exercise receipt of a configuration
			// already decided before the local orderer can authorize it.
			require.NoError(t, native.Node.Propose(t.Context(), raw))
		} else {
			require.NoError(t, native.Configure(envelope, 0))
		}
		<-time.After(10 * time.Second)
		t.Fatal("subprocess did not reach interruption point")
	}
}

func pq40dNode(t *testing.T, root string, raftID uint64, rpc etcdraft.RPC, probe func(string)) (*etcdraft.Chain, *activation.Channel, blockledger.ReadWriter, *ChainSupport, error) {
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
	raftMeta, err := protoutil.GetConsenterMetadataFromBlock(tip)
	require.NoError(t, err)
	configuration, _, err := etcdraft.ConsensusMetadataFromConfigBlock(config)
	require.NoError(t, err)
	meta, err := etcdraft.ReadBlockMetadata(raftMeta, configuration)
	require.NoError(t, err)
	supported := pq40dSupport{support, func() {
		if probe != nil {
			probe("before-guard")
		}
	}}
	native, err := etcdraft.NewChain(supported, etcdraft.Options{
		RaftID: raftID, WALDir: filepath.Join(root, "wal"), SnapDir: filepath.Join(root, "snap"),
		Clock: clock.NewClock(), MemoryStorage: raft.NewMemoryStorage(),
		Logger: flogging.MustGetLogger("pq40d.test"), Metrics: etcdraft.NewMetrics(&disabled.Provider{}),
		TickInterval: 10 * time.Millisecond, ElectionTick: 10, HeartbeatTick: 1,
		MaxSizePerMsg: 1 << 20, MaxInflightBlocks: 4, EvictionSuspicion: time.Hour,
		BlockMetadata: meta, Consenters: etcdraft.CreateConsentersMap(meta, configuration),
	}, pq40dConfigurator{}, rpc, fixture.Crypto, nil, nil, nil)
	return native, &controller, ledger, support, err
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
	genesis := pq40dGenesis(t, 3)
	nodes := map[uint64]*etcdraft.Chain{}
	roots := map[uint64]string{}
	ledgers := map[uint64]blockledger.ReadWriter{}
	for id := uint64(1); id <= 3; id++ {
		root := t.TempDir()
		roots[id] = root
		pq40dProvisionGenesis(t, root, proto.CloneOf(genesis), true)
		node, _, ledger, _, err := pq40dNode(t, root, id, pq40dTransport{id: id, nodes: nodes}, nil)
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
}
