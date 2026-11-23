// SPDX-License-Identifier: Apache-2.0

package etcdraft

import (
	"errors"
	"testing"

	"github.com/hyperledger/fabric-protos-go-apiv2/orderer/etcdraft"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation"
	"github.com/stretchr/testify/require"
	"go.etcd.io/raft/v3"
	"go.etcd.io/raft/v3/raftpb"
)

func TestPQ40DRejectsStaleReadIndex(t *testing.T) {
	channel := &activation.Channel{Gate: &activation.Gate{}}
	barrier := replayBarrier{term: 1, leader: 2, requestID: []byte("old")}
	var next raft.Status
	next.HardState = &raftpb.HardState{Term: new(uint64(2))}
	next.Lead = 3
	barrier.observe(raft.Ready{ReadStates: []raft.ReadState{{Index: 10, RequestCtx: []byte("old")}}}, next, channel)
	require.Zero(t, barrier.index)
	barrier.requestID = []byte("current")
	barrier.observe(raft.Ready{ReadStates: []raft.ReadState{{Index: 11, RequestCtx: []byte("current")}}}, next, channel)
	require.Equal(t, uint64(11), barrier.index)
}

func TestPQ40DRequiresNativeReplayProgress(t *testing.T) {
	durable := errors.New("reached ledger durability check")
	c := &Chain{
		activation: &activation.Channel{
			Gate:   &activation.Gate{},
			Ledger: activation.Ledger{Sync: func() error { return durable }},
		},
		opts:         Options{BlockMetadata: &etcdraft.BlockMetadata{ConsenterIds: []uint64{1}}},
		confState:    &raftpb.ConfState{Voters: []uint64{1}},
		appliedIndex: 5,
	}
	require.NoError(t, c.reconcileReplay(&replayProgress{commit: 5, last: 5}))
	require.NoError(t, c.reconcileReplay(&replayProgress{commit: 5, read: 6, last: 5}))
	require.NoError(t, c.reconcileReplay(&replayProgress{commit: 6, read: 5, last: 6}))
	require.NoError(t, c.reconcileReplay(&replayProgress{commit: 5, read: 5, last: 6}))
	require.False(t, c.activation.Ready())
	require.ErrorIs(t, c.reconcileReplay(&replayProgress{commit: 5, read: 5, last: 5}), durable)
}
