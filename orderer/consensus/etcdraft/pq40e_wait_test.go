/*
SPDX-License-Identifier: Apache-2.0
*/

package etcdraft

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hyperledger/fabric-lib-go/common/metrics/disabled"
	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-protos-go-apiv2/orderer"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation/testfixture"
	"github.com/stretchr/testify/require"
	"go.etcd.io/raft/v3/raftpb"
)

func TestPQ40EReadinessWaitStopsWithGeneration(t *testing.T) {
	start := make(chan struct{})
	close(start)
	chain := &Chain{startC: start, doneC: make(chan struct{}), submitC: make(chan *submit)}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- chain.WaitReadyWithGeneration(ctx) }()
	cancel()
	select {
	case err := <-result:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("readiness wait did not stop with its generation")
	}
}

func TestPQ40ESnapshotReportsAuthorizationErrorBeforeShutdown(t *testing.T) {
	chain := &Chain{snapshotRequests: make(chan snapshotRequest), doneC: make(chan struct{}), applicationDone: make(chan struct{})}
	expected := errors.New("snapshot authorization failed")
	go func() {
		request := <-chain.snapshotRequests
		request.result <- expected
		close(chain.doneC)
		close(chain.applicationDone)
	}()
	require.ErrorIs(t, chain.authorizeIncomingSnapshot(&raftpb.Message{}), expected)
}

func TestPQ40ESnapshotReturnsOnHaltWithBlockedApplication(t *testing.T) {
	chain := &Chain{snapshotRequests: make(chan snapshotRequest), doneC: make(chan struct{}), applicationDone: make(chan struct{})}
	finish := make(chan struct{})
	defer close(finish)
	go func() {
		<-chain.snapshotRequests
		close(chain.doneC)
		<-finish
		close(chain.applicationDone)
	}()
	result := make(chan error, 1)
	go func() { result <- chain.authorizeIncomingSnapshot(&raftpb.Message{}) }()
	select {
	case err := <-result:
		require.ErrorIs(t, err, ErrChainHalting)
	case <-time.After(5 * time.Second):
		t.Fatal("snapshot request did not return after external halt")
	}
}

type protectedForwardTransport struct {
	RPC
	started chan struct{}
}

func (p *protectedForwardTransport) SendSubmitWithGeneration(ctx context.Context, gate *activation.Gate, expected context.Context, _ uint64, _ *orderer.SubmitRequest, report func(error)) error {
	_, _, release, ok := gate.AcquireMatching(expected)
	if !ok {
		return errors.New("stale generation")
	}
	go func() {
		defer release()
		close(p.started)
		<-ctx.Done()
		report(ctx.Err())
	}()
	return nil
}

func TestPQ40EProtectedForwardStopsWithGeneration(t *testing.T) {
	fixture := testfixture.New(t)
	genesis := testfixture.Genesis(t)
	store, err := activation.OpenStore(t.TempDir(), nil)
	require.NoError(t, err)
	fixture.Provision(t, store, testfixture.Config(t, genesis))
	controller := fixture.Channel(store, activation.Ledger{
		LatestConfig: func() (*cb.Block, error) { return genesis, nil },
		Block: func(number uint64) (*cb.Block, error) {
			if number != 0 {
				return nil, errors.New("missing block")
			}
			return genesis, nil
		},
		Height: func() (uint64, error) { return 1, nil },
		Sync:   func() error { return nil },
	})
	require.NoError(t, controller.Recover(true))
	transport := &protectedForwardTransport{started: make(chan struct{})}
	chain := &Chain{activation: &controller, rpc: transport, opts: Options{RPCTimeout: 5 * time.Second}, Metrics: NewMetrics(&disabled.Provider{}), doneC: make(chan struct{})}
	result := make(chan error, 1)
	go func() { result <- chain.forwardProtectedToLeader(1, &orderer.SubmitRequest{}) }()
	select {
	case <-transport.started:
	case <-time.After(5 * time.Second):
		t.Fatal("protected send did not start")
	}
	drained := make(chan struct{})
	go func() { controller.Suspend(); close(drained) }()
	select {
	case err := <-result:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("protected forwarding did not stop")
	}
	select {
	case <-drained:
	case <-time.After(5 * time.Second):
		t.Fatal("protected stream did not release its lease")
	}
	require.ErrorContains(t, chain.forwardProtectedToLeader(1, &orderer.SubmitRequest{}), "admission is closed")
}
