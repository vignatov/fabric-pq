//go:build linux

// SPDX-License-Identifier: Apache-2.0

package multichannel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
)

const pq40dCrash = 79

type pq40dConfigurator struct{}

func (pq40dConfigurator) Configure(string, []cluster.RemoteNode) {}

type pq40dSupport struct {
	*ChainSupport
	beforeApply func()
}

func (s pq40dSupport) WaitForBlockCommit() {
	s.ChainSupport.WaitForBlockCommit()
	s.beforeApply()
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
	fixture := testfixture.New(t)
	genesis := testfixture.Genesis(t)
	envelope, err := protoutil.ExtractEnvelope(genesis, 0)
	require.NoError(t, err)
	config := &cb.ConfigEnvelope{}
	_, err = protoutil.UnmarshalEnvelopeOfType(envelope, cb.HeaderType_CONFIG, config)
	require.NoError(t, err)
	metadata := &pb.ConfigMetadata{
		Consenters: []*pb.Consenter{{Host: "localhost", Port: 7050, ClientTlsCert: []byte("test-only"), ServerTlsCert: []byte("test-only")}},
		Options:    &pb.Options{TickInterval: "10ms", HeartbeatTick: 1, ElectionTick: 5, MaxInflightBlocks: 4},
	}
	config.GetConfig().GetChannelGroup().GetGroups()["Orderer"].GetValues()["ConsensusType"].Value =
		protoutil.MarshalOrPanic(&ab.ConsensusType{Type: "etcdraft", Metadata: protoutil.MarshalOrPanic(metadata)})
	genesis.Data.Data[0] = protoutil.MarshalOrPanic(fixture.Envelope(t, config))
	genesis.Header.DataHash = protoutil.ComputeBlockDataHash(genesis.Data)

	factory := newFactory(filepath.Join(root, "ledger"))
	lgr, err := factory.GetOrCreate(testfixture.ChannelID)
	require.NoError(t, err)
	require.NoError(t, lgr.Append(genesis))
	factory.Close()

	store, err := activation.OpenStore(root, nil)
	require.NoError(t, err)
	base := config.GetConfig()
	fixture.Provision(t, store, base)
	id := sha256.Sum256([]byte(testfixture.ChannelID))
	hash, err := json.Marshal(hex.EncodeToString(protoutil.BlockHeaderHash(genesis.Header)))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(root, fmt.Sprintf("genesis-%x", id)), hash, 0o600))
	update := fixture.Update(t, base)
	candidate := protoutil.NewBlock(1, protoutil.BlockHeaderHash(genesis.Header))
	candidate.Data = &cb.BlockData{Data: [][]byte{protoutil.MarshalOrPanic(fixture.Envelope(t, update))}}
	candidate.Header.DataHash = protoutil.ComputeBlockDataHash(candidate.Data)
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
	fixture := testfixture.New(t)
	ledger, view := ordererActivationLedger(t, filepath.Join(root, "ledger"), func(string) {})
	genesis, err := view.Block(0)
	require.NoError(t, err)
	tip, err := view.LatestConfig()
	require.NoError(t, err)
	var armed atomic.Bool
	crash := func(boundary string) {
		if mode == boundary && armed.Load() {
			os.Exit(pq40dCrash)
		}
	}
	store, err := activation.OpenStore(root, crash)
	require.NoError(t, err)
	controller := fixture.Channel(store, view)
	writer, support := activationWriter(t, fixture, ledger, tip)
	support.BlockWriter = writer
	support.activation = &controller
	support.cutter = blockcutter.NewReceiverImpl(testfixture.ChannelID, support, blockcutter.NewMetrics(&disabled.Provider{}))
	raw, err := os.ReadFile(filepath.Join(root, "candidate"))
	require.NoError(t, err)
	candidate, err := protoutil.UnmarshalBlock(raw)
	require.NoError(t, err)
	raftMeta, err := protoutil.GetConsenterMetadataFromBlock(tip)
	require.NoError(t, err)
	consenters := []*pb.Consenter{{Host: "localhost", Port: 7050, ClientTlsCert: []byte("test-only"), ServerTlsCert: []byte("test-only")}}
	meta, err := etcdraft.ReadBlockMetadata(raftMeta, &pb.ConfigMetadata{Consenters: consenters})
	require.NoError(t, err)
	native, err := etcdraft.NewChain(pq40dSupport{support, func() { crash("before-guard") }}, etcdraft.Options{
		RaftID: 1, WALDir: filepath.Join(root, "wal"), SnapDir: filepath.Join(root, "snap"),
		Clock: clock.NewClock(), MemoryStorage: raft.NewMemoryStorage(),
		Logger: flogging.MustGetLogger("pq40d.test"), Metrics: etcdraft.NewMetrics(&disabled.Provider{}),
		TickInterval: 10 * time.Millisecond, ElectionTick: 5, HeartbeatTick: 1,
		MaxSizePerMsg: 1 << 20, MaxInflightBlocks: 4,
		BlockMetadata: meta, Consenters: etcdraft.CreateConsentersMap(meta, &pb.ConfigMetadata{Consenters: consenters}),
	}, pq40dConfigurator{}, nil, fixture.Crypto, nil, nil, nil)
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
		block, err := view.Block(1)
		require.NoError(t, err)
		require.Equal(t, candidate.Header, block.Header)
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
