/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package comm

import (
	"context"
	"sync"

	"github.com/hyperledger/fabric-lib-go/common/metrics"
	"google.golang.org/grpc/stats"
)

type ServerStatsHandler struct {
	OpenConnCounter   metrics.Counter
	ClosedConnCounter metrics.Counter
}

type responseLeaseKey struct{}

type responseLeaseScope struct {
	mu       sync.Mutex
	begun    bool
	unary    bool
	ended    bool
	releases []func()
}

// RetainUntilRPCEnd transfers a lease to a unary gRPC response lifecycle. It
// returns false without taking ownership for streams or absent server scopes.
func RetainUntilRPCEnd(ctx context.Context, release func()) bool {
	return retainUntilRPCEnd(ctx, true, release)
}

func retainUntilRPCEnd(ctx context.Context, unary bool, release func()) bool {
	scope, ok := ctx.Value(responseLeaseKey{}).(*responseLeaseScope)
	if !ok || release == nil {
		return false
	}
	scope.mu.Lock()
	defer scope.mu.Unlock()
	if !scope.begun || scope.unary != unary || scope.ended {
		return false
	}
	scope.releases = append(scope.releases, sync.OnceFunc(release))
	return true
}

func (h *ServerStatsHandler) TagRPC(ctx context.Context, info *stats.RPCTagInfo) context.Context {
	return context.WithValue(ctx, responseLeaseKey{}, &responseLeaseScope{})
}

func (h *ServerStatsHandler) HandleRPC(ctx context.Context, s stats.RPCStats) {
	scope, ok := ctx.Value(responseLeaseKey{}).(*responseLeaseScope)
	if !ok {
		return
	}
	if begin, ok := s.(*stats.Begin); ok {
		scope.mu.Lock()
		if !scope.ended {
			scope.begun = true
			scope.unary = !begin.IsClientStream && !begin.IsServerStream
		}
		scope.mu.Unlock()
		return
	}
	if _, ok := s.(*stats.End); !ok {
		return
	}
	scope.mu.Lock()
	if scope.ended {
		scope.mu.Unlock()
		return
	}
	scope.ended = true
	releases := scope.releases
	scope.releases = nil
	scope.mu.Unlock()
	for _, release := range releases {
		release()
	}
}

func (h *ServerStatsHandler) TagConn(ctx context.Context, info *stats.ConnTagInfo) context.Context {
	return ctx
}

func (h *ServerStatsHandler) HandleConn(ctx context.Context, s stats.ConnStats) {
	switch s.(type) {
	case *stats.ConnBegin:
		h.OpenConnCounter.Add(1)
	case *stats.ConnEnd:
		h.ClosedConnCounter.Add(1)
	}
}
