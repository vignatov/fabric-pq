/*
SPDX-License-Identifier: Apache-2.0
*/

package activation

import (
	"context"
	"sync"

	"github.com/hyperledger/fabric/common/channelconfig"
)

// Gate admits operations to one immutable serving bundle at a time. Its zero
// value is closed. The controller is its sole publisher.
type Gate struct {
	mu      sync.Mutex
	current *generation
}

type generation struct {
	ctx    context.Context
	cancel context.CancelFunc
	bundle *channelconfig.Bundle
	work   sync.WaitGroup
}

var closedAdmission = func() <-chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}()

// Errored closes when the currently active generation stops admitting work.
func (g *Gate) Errored() <-chan struct{} {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.current == nil {
		return closedAdmission
	}
	return g.current.ctx.Done()
}

func (g *Gate) isOpen() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.current != nil
}

// Acquire obtains a bundle and a generation context. Callers must release the
// lease and use the context to cancel work at their dispatch and send boundaries.
func (g *Gate) Acquire() (*channelconfig.Bundle, context.Context, func(), bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.current == nil {
		return nil, nil, nil, false
	}
	current := g.current
	current.work.Add(1)
	return current.bundle, current.ctx, sync.OnceFunc(current.work.Done), true
}

func (g *Gate) close() {
	if current := g.stop(); current != nil {
		current.work.Wait()
	}
}

func (g *Gate) stop() *generation {
	g.mu.Lock()
	current := g.current
	g.current = nil
	g.mu.Unlock()
	if current != nil {
		current.cancel()
	}
	return current
}

func (g *Gate) publish(bundle *channelconfig.Bundle) {
	g.mu.Lock()
	defer g.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	g.current = &generation{bundle: bundle, ctx: ctx, cancel: cancel}
}
