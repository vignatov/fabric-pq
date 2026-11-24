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
	ended    bool
	releases []func()
}

// RetainUntilRPCEnd transfers a lease to the gRPC response lifecycle. It
// returns false without taking ownership when no live server scope is present.
func RetainUntilRPCEnd(ctx context.Context, release func()) bool {
	scope, ok := ctx.Value(responseLeaseKey{}).(*responseLeaseScope)
	if !ok || release == nil {
		return false
	}
	scope.mu.Lock()
	defer scope.mu.Unlock()
	if scope.ended {
		return false
	}
	scope.releases = append(scope.releases, sync.OnceFunc(release))
	return true
}

func (h *ServerStatsHandler) TagRPC(ctx context.Context, info *stats.RPCTagInfo) context.Context {
	return context.WithValue(ctx, responseLeaseKey{}, &responseLeaseScope{})
}

func (h *ServerStatsHandler) HandleRPC(ctx context.Context, s stats.RPCStats) {
	if _, ok := s.(*stats.End); !ok {
		return
	}
	scope, ok := ctx.Value(responseLeaseKey{}).(*responseLeaseScope)
	if !ok {
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
