/*
SPDX-License-Identifier: Apache-2.0
*/

package etcdraft

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
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
