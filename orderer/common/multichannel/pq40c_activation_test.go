//go:build linux

/*
SPDX-License-Identifier: Apache-2.0
*/

package multichannel

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-protos-go-apiv2/orderer/etcdraft"
	"github.com/hyperledger/fabric/common/channelconfig"
	"github.com/hyperledger/fabric/common/ledger/blockledger"
	"github.com/hyperledger/fabric/common/policies"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation/testfixture"
	"github.com/hyperledger/fabric/protoutil"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

type activationWriterLedger struct {
	blockledger.ReadWriter
	probe func(string)
}

func (l activationWriterLedger) Append(block *cb.Block) error {
	l.probe("writer-before-append")
	if err := l.ReadWriter.Append(block); err != nil {
		return err
	}
	l.probe("writer-after-append")
	return nil
}

func ordererActivationLedger(t *testing.T, root string, probe func(string)) (blockledger.ReadWriter, activation.Ledger) {
	t.Helper()
	factory := newFactory(root)
	t.Cleanup(factory.Close)
	lgr, err := factory.GetOrCreate(testfixture.ChannelID)
	require.NoError(t, err)
	block := func(number uint64) (*cb.Block, error) {
		value := blockledger.GetBlock(lgr, number)
		if value == nil {
			return nil, fmt.Errorf("ledger block %d does not exist", number)
		}
		return value, nil
	}
	return activationWriterLedger{ReadWriter: lgr, probe: probe}, activation.Ledger{
		Block:  block,
		Height: func() (uint64, error) { return lgr.Height(), nil },
		LatestConfig: func() (*cb.Block, error) {
			if lgr.Height() == 0 {
				return nil, errors.New("missing genesis block")
			}
			last, err := block(lgr.Height() - 1)
			if err != nil {
				return nil, err
			}
			index, err := protoutil.GetLastConfigIndexFromBlock(last)
			if err != nil {
				return nil, err
			}
			return block(index)
		},
		Sync: func() error { return activation.SyncDirectory(filepath.Join(root, "chains", testfixture.ChannelID)) },
	}
}

func activationWriter(t *testing.T, fixture testfixture.Fixture, ledger blockledger.ReadWriter, genesis *cb.Block) (*BlockWriter, *ChainSupport) {
	t.Helper()
	bundle, err := channelconfig.NewBundle(testfixture.ChannelID, testfixture.Config(t, genesis), fixture.Crypto)
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
	return newBlockWriter(genesis, support), support
}

func TestPQ40COrdererActivation(t *testing.T) {
	testOrdererActivation(t, false)
}

func TestPQ40B1ProtectedOrdererActivation(t *testing.T) {
	testOrdererActivation(t, true)
}

func testOrdererActivation(t *testing.T, transportCapability bool) {
	fixture := testfixture.New(t)
	genesis := testfixture.Genesis(t)
	if transportCapability {
		genesis = testfixture.TransportGenesis(t)
	}
	base := testfixture.Config(t, genesis)
	store, err := activation.OpenStore(t.TempDir(), nil)
	require.NoError(t, err)
	fixture.Provision(t, store, base)
	lgr, view := ordererActivationLedger(t, t.TempDir(), func(string) {})
	require.NoError(t, lgr.Append(genesis))
	controller := fixture.Channel(store, view)
	controller.Validate = checkResources
	require.ErrorContains(t, controller.Recover(false), "native replay must settle")
	_, _, _, admitted := controller.Gate.Acquire()
	require.False(t, admitted)
	require.NoError(t, controller.Recover(true))
	old, lease, release, admitted := controller.Gate.Acquire()
	require.True(t, admitted)
	t.Cleanup(release)
	writer, private := activationWriter(t, fixture, lgr, genesis)
	update := fixture.Update(t, base)
	auth := fixture.Authorize(t, 1, base, update.GetConfig())
	next := writer.CreateNextBlock([]*cb.Envelope{fixture.Envelope(t, update)})
	metadata := protoutil.MarshalOrPanic(&etcdraft.BlockMetadata{RaftIndex: 7})
	committing := make(chan struct{})
	permitCommit := make(chan struct{})
	completed := make(chan error, 1)
	go func() {
		completed <- controller.Apply(next, auth, func() error {
			close(committing)
			<-permitCommit
			writer.WriteConfigBlock(next, metadata)
			return nil
		})
	}()
	t.Cleanup(func() { close(permitCommit) })
	select {
	case <-lease.Done():
	case err := <-completed:
		t.Fatalf("activation did not cancel old generation: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("activation did not drain the old generation")
	}
	select {
	case <-committing:
		t.Fatal("commit started while an old lease was outstanding")
	default:
	}
	require.Zero(t, old.ConfigtxValidator().Sequence())
	_, _, _, admitted = controller.Gate.Acquire()
	require.False(t, admitted)
	release()
	select {
	case <-committing:
	case err := <-completed:
		t.Fatalf("activation did not reach native commit: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("activation did not reach native commit")
	}
	_, _, _, admitted = controller.Gate.Acquire()
	require.False(t, admitted)
	permitCommit <- struct{}{}
	require.NoError(t, <-completed)
	current, _, releaseCurrent, admitted := controller.Gate.Acquire()
	require.True(t, admitted)
	releaseCurrent()
	require.Equal(t, uint64(1), current.ConfigtxValidator().Sequence())
	require.Equal(t, uint64(1), private.Sequence())
	committed, err := view.Block(1)
	require.NoError(t, err)
	require.True(t, proto.Equal(next, committed))
	verifyActivationMetadata(t, committed, old, metadata)
	normalEnv, err := protoutil.CreateSignedEnvelope(cb.HeaderType_MESSAGE, testfixture.ChannelID, fixture.Fabric, &cb.Config{}, 0, 0)
	require.NoError(t, err)
	normal := writer.CreateNextBlock([]*cb.Envelope{normalEnv})
	writer.WriteBlockSync(normal, metadata)
	committed, err = view.Block(2)
	require.NoError(t, err)
	verifyActivationMetadata(t, committed, current, metadata)
	require.ErrorContains(t, controller.Apply(next, auth, func() error {
		t.Fatal("replayed configuration entered native commit")
		return nil
	}), "Fabric config authorization")
}

func verifyActivationMetadata(t *testing.T, block *cb.Block, bundle *channelconfig.Bundle, raftMetadata []byte) {
	t.Helper()
	lastConfig, err := protoutil.GetLastConfigIndexFromBlock(block)
	require.NoError(t, err)
	require.Equal(t, uint64(1), lastConfig)
	legacy, err := protoutil.GetMetadataFromBlock(block, cb.BlockMetadataIndex_LAST_CONFIG)
	require.NoError(t, err)
	legacyIndex := &cb.LastConfig{}
	require.NoError(t, proto.Unmarshal(legacy.GetValue(), legacyIndex))
	require.Equal(t, uint64(1), legacyIndex.GetIndex())
	consenter, err := protoutil.GetConsenterMetadataFromBlock(block)
	require.NoError(t, err)
	require.Equal(t, raftMetadata, consenter.GetValue())
	policy, ok := bundle.PolicyManager().GetPolicy(policies.BlockValidation)
	require.True(t, ok)
	require.NoError(t, protoutil.BlockSignatureVerifier(false, nil, policy)(block.GetHeader(), block.GetMetadata()))
}

func TestPQ40COrdererUncertainCommit(t *testing.T) {
	testOrdererUncertainCommit(t, false)
}

func TestPQ40B1OrdererUncertainCommit(t *testing.T) {
	testOrdererUncertainCommit(t, true)
}

func testOrdererUncertainCommit(t *testing.T, transportCapability bool) {
	for _, scenario := range []struct {
		name   string
		append bool
	}{{name: "before append"}, {name: "after append", append: true}} {
		t.Run(scenario.name, func(t *testing.T) {
			fixture := testfixture.New(t)
			genesis := testfixture.Genesis(t)
			if transportCapability {
				genesis = testfixture.TransportGenesis(t)
			}
			base := testfixture.Config(t, genesis)
			store, err := activation.OpenStore(t.TempDir(), nil)
			require.NoError(t, err)
			fixture.Provision(t, store, base)
			lgr, view := ordererActivationLedger(t, t.TempDir(), func(string) {})
			require.NoError(t, lgr.Append(genesis))
			controller := fixture.Channel(store, view)
			controller.Validate = checkResources
			require.NoError(t, controller.Recover(true))
			writer, _ := activationWriter(t, fixture, lgr, genesis)
			update := fixture.Update(t, base)
			next := writer.CreateNextBlock([]*cb.Envelope{fixture.Envelope(t, update)})
			auth := fixture.Authorize(t, 1, base, update.GetConfig())
			fault := errors.New("simulated commit failure")
			err = controller.Apply(next, auth, func() error {
				if scenario.append {
					writer.WriteConfigBlock(next, nil)
				}
				return fault
			})
			require.ErrorIs(t, err, fault)
			_, _, _, admitted := controller.Gate.Acquire()
			require.False(t, admitted)
			require.NoError(t, controller.Recover(true))
			bundle, _, release, admitted := controller.Gate.Acquire()
			require.True(t, admitted)
			defer release()
			want := uint64(0)
			if scenario.append {
				want = 1
			}
			require.Equal(t, want, bundle.ConfigtxValidator().Sequence())
		})
	}
}

func TestPQ40COrdererCrashRecovery(t *testing.T) {
	testOrdererCrashRecovery(t, false)
}

func TestPQ40B1OrdererCrashRecovery(t *testing.T) {
	testOrdererCrashRecovery(t, true)
}

func testOrdererCrashRecovery(t *testing.T, transportCapability bool) {
	for _, scenario := range []struct {
		point      string
		occurrence int
		committed  bool
		advanced   bool
	}{
		{point: "before-prepare", occurrence: 1},
		{point: "journal:file-synced", occurrence: 1},
		{point: "journal:durable", occurrence: 1},
		{point: "journal:durable", occurrence: 2},
		{point: "writer-before-append", occurrence: 1},
		{point: "writer-after-append", occurrence: 1, committed: true},
		{point: "ledger-durable", occurrence: 1, committed: true},
		{point: "checkpoint:file-synced", occurrence: 1, committed: true},
		{point: "checkpoint:renamed", occurrence: 1, committed: true, advanced: true},
		{point: "checkpoint:durable", occurrence: 1, committed: true, advanced: true},
		{point: "before-publication", occurrence: 1, committed: true, advanced: true},
		{point: "during-publication", occurrence: 1, committed: true, advanced: true},
		{point: "after-publication", occurrence: 1, committed: true, advanced: true},
		{point: "journal:durable", occurrence: 3, committed: true, advanced: true},
		{point: "active", occurrence: 1, committed: true, advanced: true},
	} {
		t.Run(fmt.Sprintf("%s/%d", scenario.point, scenario.occurrence), func(t *testing.T) {
			root := t.TempDir()
			worker := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestPQ40COrdererCrashWorker$")
			worker.Env = append(os.Environ(), "PQ40C_CRASH_ROOT="+root, "PQ40C_CRASH_POINT="+fmt.Sprintf("%s/%d", scenario.point, scenario.occurrence), fmt.Sprintf("PQ40B1_CAPABILITY=%t", transportCapability))
			output, err := worker.CombinedOutput()
			var exit *exec.ExitError
			require.ErrorAs(t, err, &exit, "%s", output)
			require.Equal(t, 86, exit.ExitCode(), "%s", output)
			fixture := testfixture.New(t)
			writes := 0
			store, err := activation.OpenStore(filepath.Join(root, "policy"), func(boundary string) {
				if boundary == "checkpoint:durable" {
					writes++
				}
			})
			require.NoError(t, err)
			_, view := ordererActivationLedger(t, filepath.Join(root, "ledger"), func(string) {})
			controller := fixture.Channel(store, view)
			controller.Validate = checkResources
			wantSequence := uint64(0)
			wantWrites := 0
			if scenario.committed {
				wantSequence = 1
				if !scenario.advanced {
					wantWrites = 1
				}
			}
			for range 2 {
				require.NoError(t, controller.Recover(true))
				bundle, _, release, admitted := controller.Gate.Acquire()
				require.True(t, admitted)
				version := bundle.ConfigtxValidator().Sequence()
				release()
				require.Equal(t, wantSequence, version)
				require.Equal(t, wantWrites, writes)
			}
		})
	}
}

func TestPQ40COrdererCrashWorker(t *testing.T) {
	root := os.Getenv("PQ40C_CRASH_ROOT")
	if root == "" {
		t.Skip("subprocess worker")
	}
	target := os.Getenv("PQ40C_CRASH_POINT")
	counts := map[string]int{}
	armed := false
	probe := func(boundary string) {
		if !armed {
			return
		}
		counts[boundary]++
		if fmt.Sprintf("%s/%d", boundary, counts[boundary]) == target {
			os.Exit(86)
		}
	}
	fixture := testfixture.New(t)
	genesis := testfixture.Genesis(t)
	if os.Getenv("PQ40B1_CAPABILITY") == "true" {
		genesis = testfixture.TransportGenesis(t)
	}
	base := testfixture.Config(t, genesis)
	policyDir := filepath.Join(root, "policy")
	require.NoError(t, os.Mkdir(policyDir, 0o700))
	require.NoError(t, activation.SyncDirectory(root))
	store, err := activation.OpenStore(policyDir, probe)
	require.NoError(t, err)
	fixture.Provision(t, store, base)
	lgr, view := ordererActivationLedger(t, filepath.Join(root, "ledger"), probe)
	require.NoError(t, lgr.Append(genesis))
	controller := fixture.Channel(store, view)
	controller.Validate = checkResources
	controller.Publish = func(*channelconfig.Bundle) error {
		probe("during-publication")
		return nil
	}
	require.NoError(t, controller.Recover(true))
	writer, _ := activationWriter(t, fixture, lgr, genesis)
	update := fixture.Update(t, base)
	block := writer.CreateNextBlock([]*cb.Envelope{fixture.Envelope(t, update)})
	auth := fixture.Authorize(t, 1, base, update.GetConfig())
	armed = true
	require.NoError(t, controller.Apply(block, auth, func() error {
		writer.WriteConfigBlock(block, nil)
		return nil
	}))
	t.Fatalf("crash boundary %q was not reached", target)
}
