/*
SPDX-License-Identifier: Apache-2.0
*/

package gateway

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/hyperledger/fabric/internal/pkg/comm"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/stats"
	"google.golang.org/grpc/status"
)

func TestPQ40EGatewayDrainsWorkerBeforeLeavingRPC(t *testing.T) {
	generation, cancelGeneration := context.WithCancel(t.Context())
	defer cancelGeneration()
	released := make(chan struct{})
	server := &Server{acquireAdmission: func(string) (context.Context, func(), bool) {
		return generation, func() { close(released) }, true
	}}
	handler := &comm.ServerStatsHandler{}
	rpc := handler.TagRPC(t.Context(), &stats.RPCTagInfo{})
	handler.HandleRPC(rpc, &stats.Begin{})
	ctx, admission, err := server.admitUnary(rpc, "channel", false)
	require.NoError(t, err)
	workerCanceled := make(chan struct{})
	finishWorker := make(chan struct{})
	finish := sync.OnceFunc(func() { close(finishWorker) })
	defer finish()
	launchGatewayWork(ctx, func() {
		<-ctx.Done()
		close(workerCanceled)
		<-finishWorker
	})
	done := make(chan error, 1)
	cancelGeneration()
	go func() {
		response := new(string)
		var err error
		finishUnary(admission, &response, &err)
		done <- err
	}()
	select {
	case <-workerCanceled:
	case <-time.After(5 * time.Second):
		t.Fatal("Gateway worker did not receive cancellation")
	}
	select {
	case <-done:
		t.Fatal("Gateway returned while the admitted worker was still running")
	default:
	}
	finish()
	select {
	case err := <-done:
		require.Equal(t, codes.Unavailable, status.Code(err))
	case <-time.After(5 * time.Second):
		t.Fatal("Gateway call did not drain")
	}
	select {
	case <-released:
		t.Fatal("Gateway released admission before the response lifecycle ended")
	default:
	}
	handler.HandleRPC(rpc, &stats.End{})
	select {
	case <-released:
	default:
		t.Fatal("response completion did not release admission")
	}
}
