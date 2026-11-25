/*
SPDX-License-Identifier: Apache-2.0
*/

package gateway

import (
	"context"
	"sync"

	"github.com/hyperledger/fabric/internal/pkg/comm"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type gatewayWorkKey struct{}

type unaryAdmission struct {
	generation context.Context
	stop       func()
	work       sync.WaitGroup
}

func (gs *Server) admitUnary(ctx context.Context, channel string, routed bool) (context.Context, *unaryAdmission, error) {
	if gs.acquireAdmission == nil {
		return ctx, nil, nil
	}
	generation, release, ok := gs.acquireAdmission(channel)
	if !ok {
		return nil, nil, status.Error(codes.Unavailable, "protected channel admission is closed")
	}
	if generation == nil {
		return ctx, nil, nil
	}
	if routed && gs.registry.endpointFactory.transportPolicy == nil {
		release()
		return nil, nil, status.Error(codes.Unavailable, "protected Gateway routing requires strict transport")
	}
	if !comm.RetainUntilRPCEnd(ctx, release) {
		release()
		return nil, nil, status.Error(codes.Unavailable, "protected Gateway call requires a unary response scope")
	}
	if generation.Err() != nil {
		return nil, nil, status.Error(codes.Unavailable, "protected channel admission is closed")
	}
	callCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(generation, cancel)
	admission := &unaryAdmission{generation: generation, stop: func() {
		stop()
		cancel()
	}}
	return context.WithValue(callCtx, gatewayWorkKey{}, &admission.work), admission, nil
}

// finishUnary stops and joins any work that outlives the handler's own waits.
// gRPC retains the generation until the resulting response has been sent.
func finishUnary[T any](admission *unaryAdmission, response **T, err *error) {
	if admission == nil {
		return
	}
	admission.stop()
	admission.work.Wait()
	if admission.generation.Err() != nil {
		*response = nil
		*err = status.Error(codes.Unavailable, "protected channel admission is closed")
	}
}

func launchGatewayWork(ctx context.Context, f func()) {
	if work, ok := ctx.Value(gatewayWorkKey{}).(*sync.WaitGroup); ok {
		work.Go(f)
		return
	}
	go f()
}
