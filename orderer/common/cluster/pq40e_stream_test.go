/*
SPDX-License-Identifier: Apache-2.0
*/

package cluster

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hyperledger/fabric-lib-go/common/flogging"
	"github.com/hyperledger/fabric-lib-go/common/metrics/disabled"
	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-protos-go-apiv2/orderer"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation/testfixture"
	"github.com/stretchr/testify/require"
)

func pq40eStream(capacity int) (*Stream, chan struct{}) {
	abort := make(chan struct{})
	var canceled uint32
	return &Stream{
		abortChan: abort, commShutdown: make(chan struct{}), sendBuff: make(chan queuedStep, capacity),
		metrics: NewMetrics(&disabled.Provider{}), canceled: &canceled,
		Logger: flogging.MustGetLogger("pq40e.stream"), Cancel: func(error) {},
	}, abort
}

func TestPQ40EGenerationSendDrainsAndRejectsOldGeneration(t *testing.T) {
	fixture := testfixture.New(t)
	genesis := testfixture.Genesis(t)
	store, err := activation.OpenStore(t.TempDir(), nil)
	require.NoError(t, err)
	fixture.Provision(t, store, testfixture.Config(t, genesis))
	controller := fixture.Channel(store, activation.Ledger{
		LatestConfig: func() (*cb.Block, error) { return genesis, nil },
		Block: func(n uint64) (*cb.Block, error) {
			if n != 0 {
				return nil, errors.New("missing block")
			}
			return genesis, nil
		},
		Height: func() (uint64, error) { return 1, nil },
		Sync:   func() error { return nil },
	})
	require.NoError(t, controller.Recover(true))
	_, generation, release, ok := controller.Gate.Acquire()
	require.True(t, ok)
	release()
	stream, abort := pq40eStream(1)
	var once sync.Once
	stream.Cancel = func(error) { once.Do(func() { atomic.StoreUint32(stream.canceled, 1); close(abort) }) }
	rpc := &RPC{Logger: flogging.MustGetLogger("pq40e.rpc"), StreamsByType: NewStreamsByType()}
	rpc.StreamsByType[SubmitOperation][1] = stream
	reported := make(chan error, 1)
	require.NoError(t, rpc.SendSubmitWithGeneration(context.Background(), controller.Gate, generation, 1, &orderer.SubmitRequest{}, func(err error) { reported <- err }))
	drained := make(chan struct{})
	go func() { controller.Suspend(); close(drained) }()
	select {
	case <-abort:
	case <-time.After(5 * time.Second):
		t.Fatal("generation did not abort stream")
	}
	select {
	case <-drained:
		t.Fatal("generation drained before queued send was discarded")
	default:
	}
	go stream.serviceStream()
	select {
	case err := <-reported:
		require.Error(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("queued send was not reported")
	}
	select {
	case <-drained:
	case <-time.After(5 * time.Second):
		t.Fatal("generation did not drain")
	}
	require.NoError(t, controller.Recover(true))
	_, _, release, ok = controller.Gate.Acquire()
	require.True(t, ok)
	release()
	other, _ := pq40eStream(1)
	require.Error(t, other.SendWithGeneration(context.Background(), controller.Gate, generation, &orderer.StepRequest{}, func(error) { t.Error("stale send reported completion") }))
	rpc.StreamsByType[SubmitOperation][1] = other
	require.Error(t, rpc.SendSubmitWithGeneration(context.Background(), controller.Gate, generation, 1, &orderer.SubmitRequest{}, func(error) { t.Error("stale RPC reported completion") }))
	require.Same(t, other, rpc.getStream(1, SubmitOperation), "a stale caller must not evict the current stream")
	controller.Suspend()
}

func TestPQ40EStreamShutdownReportsQueuedRequests(t *testing.T) {
	stream, _ := pq40eStream(2)
	reports := make(chan error, 2)
	for range 2 {
		require.NoError(t, stream.SendWithReport(&orderer.StepRequest{}, func(err error) { reports <- err }))
	}
	cause := errors.New("stream stopped")
	stream.failQueued(cause)
	for range 2 {
		select {
		case err := <-reports:
			require.ErrorIs(t, err, cause)
		case <-time.After(5 * time.Second):
			t.Fatal("queued request did not receive a shutdown report")
		}
	}
	require.ErrorContains(t, stream.SendWithReport(&orderer.StepRequest{}, func(error) {}), "stream is closed")
}

func TestPQ40EStreamShutdownUnblocksFullQueue(t *testing.T) {
	stream, abort := pq40eStream(1)
	reports := make(chan error, 1)
	require.NoError(t, stream.SendWithReport(&orderer.StepRequest{}, func(err error) { reports <- err }))
	entered := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		close(entered)
		result <- stream.SendWithReport(&orderer.StepRequest{}, func(error) {})
	}()
	<-entered
	close(abort)
	stream.failQueued(errors.New("stream stopped"))
	select {
	case err := <-result:
		require.Error(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown did not unblock a full queue")
	}
	select {
	case err := <-reports:
		require.ErrorContains(t, err, "stream stopped")
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown did not report the queued request")
	}
}

func TestPQ40ECanceledStreamEnqueue(t *testing.T) {
	stream, _ := pq40eStream(0)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- stream.SendWithReportContext(ctx, &orderer.StepRequest{}, func(error) {
			t.Error("a request that was not enqueued must not report completion")
		})
	}()
	cancel()
	select {
	case err := <-result:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("canceled enqueue did not return")
	}
}

func TestPQ40ECanceledQueuedStreamRequest(t *testing.T) {
	stream, abort := pq40eStream(1)
	ctx, cancel := context.WithCancel(context.Background())
	reported := make(chan error, 1)
	require.NoError(t, stream.SendWithReportContext(ctx, &orderer.StepRequest{}, func(err error) { reported <- err }))
	cancel()
	done := make(chan struct{})
	go func() { stream.serviceStream(); close(done) }()
	select {
	case err := <-reported:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("canceled queued request was not reported")
	}
	close(abort)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("stream did not stop")
	}
}

func TestPQ40ECanceledInFlightStreamOperationDrainsBeforeReport(t *testing.T) {
	stream, abort := pq40eStream(0)
	stream.Timeout = 5 * time.Second
	var abortOnce sync.Once
	stream.Cancel = func(error) { abortOnce.Do(func() { close(abort) }) }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	finished := make(chan struct{})
	reported := make(chan error, 1)
	returned := make(chan error, 1)
	go func() {
		_, err := stream.operateWithTimeoutContext(ctx, func() (*orderer.StepResponse, error) {
			close(started)
			<-abort
			close(finished)
			return nil, errors.New("transport canceled")
		}, func(err error) { reported <- err })
		returned <- err
	}()
	<-started
	cancel()
	select {
	case err := <-reported:
		require.ErrorIs(t, err, context.Canceled)
		select {
		case <-finished:
		default:
			t.Fatal("completion was reported before the in-flight operation stopped")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("canceled in-flight operation did not report")
	}
	require.ErrorIs(t, <-returned, context.Canceled)
}
