/*
SPDX-License-Identifier: Apache-2.0
*/

package broadcast_test

import (
	"context"
	"testing"

	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric/orderer/common/broadcast"
	"github.com/hyperledger/fabric/orderer/common/broadcast/mock"
	"github.com/stretchr/testify/require"
)

type guardedBroadcastSupport struct {
	*mock.ChannelSupport
	acquire func() (context.Context, func(), bool)
}

type generationReadySupport struct {
	*guardedBroadcastSupport
	wait func(context.Context) error
}

func (s *generationReadySupport) WaitReadyWithGeneration(ctx context.Context) error {
	return s.wait(ctx)
}

func (s *guardedBroadcastSupport) AcquireBroadcastAdmission() (context.Context, func(), bool) {
	return s.acquire()
}

func TestPQ40EBroadcastGenerationAdmission(t *testing.T) {
	for _, config := range []bool{false, true} {
		t.Run(map[bool]string{false: "normal", true: "config"}[config], func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			released := 0
			support := &guardedBroadcastSupport{ChannelSupport: &mock.ChannelSupport{}}
			support.acquire = func() (context.Context, func(), bool) {
				return ctx, func() { released++ }, true
			}
			support.WaitReadyCalls(func() error {
				require.Equal(t, 1, released, "validation lease must not span the blocking handoff")
				return nil
			})
			if config {
				support.ProcessConfigUpdateMsgCalls(func(*cb.Envelope) (*cb.Envelope, uint64, error) {
					cancel()
					return &cb.Envelope{}, 1, nil
				})
			} else {
				support.ProcessNormalMsgCalls(func(*cb.Envelope) (uint64, error) {
					cancel()
					return 1, nil
				})
			}
			registrar := &mock.ChannelSupportRegistrar{}
			registrar.BroadcastChannelSupportReturns(&cb.ChannelHeader{ChannelId: "channel"}, config, support, nil)
			validate := &mock.MetricsHistogram{}
			validate.WithReturns(validate)
			enqueue := &mock.MetricsHistogram{}
			enqueue.WithReturns(enqueue)
			counter := &mock.MetricsCounter{}
			counter.WithReturns(counter)
			handler := &broadcast.Handler{SupportRegistrar: registrar, Metrics: &broadcast.Metrics{
				ValidateDuration: validate, EnqueueDuration: enqueue, ProcessedCount: counter,
			}}
			response := handler.ProcessMessage(&cb.Envelope{}, "client")
			require.Equal(t, cb.Status_SERVICE_UNAVAILABLE, response.GetStatus())
			require.Equal(t, 1, released)
			require.Zero(t, support.OrderCallCount())
			require.Zero(t, support.ConfigureCallCount())
		})
	}
}

func TestPQ40EBroadcastRejectsClosedGeneration(t *testing.T) {
	support := &guardedBroadcastSupport{ChannelSupport: &mock.ChannelSupport{}}
	support.acquire = func() (context.Context, func(), bool) { return nil, nil, false }
	registrar := &mock.ChannelSupportRegistrar{}
	registrar.BroadcastChannelSupportReturns(&cb.ChannelHeader{ChannelId: "channel"}, false, support, nil)
	validate := &mock.MetricsHistogram{}
	validate.WithReturns(validate)
	enqueue := &mock.MetricsHistogram{}
	enqueue.WithReturns(enqueue)
	counter := &mock.MetricsCounter{}
	counter.WithReturns(counter)
	handler := &broadcast.Handler{SupportRegistrar: registrar, Metrics: &broadcast.Metrics{
		ValidateDuration: validate, EnqueueDuration: enqueue, ProcessedCount: counter,
	}}
	response := handler.ProcessMessage(&cb.Envelope{}, "client")
	require.Equal(t, cb.Status_SERVICE_UNAVAILABLE, response.GetStatus())
	require.Zero(t, support.ProcessNormalMsgCallCount())
}

func TestPQ40EBroadcastCancelsGenerationReadiness(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	base := &guardedBroadcastSupport{ChannelSupport: &mock.ChannelSupport{}}
	base.acquire = func() (context.Context, func(), bool) { return ctx, func() {}, true }
	base.ProcessNormalMsgReturns(1, nil)
	support := &generationReadySupport{guardedBroadcastSupport: base}
	support.wait = func(generation context.Context) error {
		require.Same(t, ctx, generation)
		cancel()
		return generation.Err()
	}
	registrar := &mock.ChannelSupportRegistrar{}
	registrar.BroadcastChannelSupportReturns(&cb.ChannelHeader{ChannelId: "channel"}, false, support, nil)
	validate := &mock.MetricsHistogram{}
	validate.WithReturns(validate)
	enqueue := &mock.MetricsHistogram{}
	enqueue.WithReturns(enqueue)
	counter := &mock.MetricsCounter{}
	counter.WithReturns(counter)
	handler := &broadcast.Handler{SupportRegistrar: registrar, Metrics: &broadcast.Metrics{
		ValidateDuration: validate, EnqueueDuration: enqueue, ProcessedCount: counter,
	}}
	response := handler.ProcessMessage(&cb.Envelope{}, "client")
	require.Equal(t, cb.Status_SERVICE_UNAVAILABLE, response.GetStatus())
	require.Zero(t, support.OrderCallCount())
}
