// SPDX-License-Identifier: Apache-2.0

package etcdraft

import (
	"errors"
	"testing"

	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-protos-go-apiv2/orderer/etcdraft"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation"
	"github.com/hyperledger/fabric/orderer/consensus/mocks"
	"github.com/hyperledger/fabric/protoutil"
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

func TestPQ40DConfChangeRequiresFabricMembership(t *testing.T) {
	support := &mocks.FakeConsenterSupport{}
	support.HeightReturns(3)
	support.BlockCalls(func(number uint64) *cb.Block {
		switch number {
		case 1:
			return pq40dBoundaryBlock(5, 1, 2)
		case 2:
			return pq40dBoundaryBlock(9, 1, 3)
		default:
			t.Fatalf("unexpected ledger read at block %d", number)
			return nil
		}
	})
	c := &Chain{
		support:   support,
		opts:      Options{BlockMetadata: &etcdraft.BlockMetadata{RaftIndex: 9, ConsenterIds: []uint64{1, 3}}},
		confState: &raftpb.ConfState{Voters: []uint64{1, 2}},
	}
	add := func(id uint64) *raftpb.ConfChange {
		return &raftpb.ConfChange{Type: new(raftpb.ConfChangeAddNode), NodeId: &id}
	}
	require.ErrorContains(t, c.validateProtectedConfChange(add(2), 10), "conflicts with authorized config")
	require.NoError(t, c.validateProtectedConfChange(add(2), 6), "previous Fabric block authorized voter 2")
	require.ErrorContains(t, c.validateProtectedConfChange(add(3), 6), "conflicts with authorized config")
	require.ErrorContains(t, c.validateProtectedConfChange(add(2), 9), "conflicts with durable Fabric block")
	require.NoError(t, c.validateProtectedConfChange(add(3), 10), "current Fabric config authorizes the new voter")
}

func TestPQ40DSnapshotVotersRequireSignedBoundary(t *testing.T) {
	block := pq40dBoundaryBlock(8, 1, 2)
	state := &raftpb.ConfState{Voters: []uint64{2, 1}}
	require.NoError(t, verifySnapshotVoters(state, block, 8))
	require.ErrorIs(t, verifySnapshotVoters(state, block, 9), errSnapshotEvidence)
	require.ErrorIs(t, verifySnapshotVoters(state, pq40dBoundaryBlock(8), 8), errSnapshotEvidence)
	require.ErrorIs(t, verifySnapshotVoters(&raftpb.ConfState{Voters: []uint64{1, 3}}, block, 8), errSnapshotVoters)
	require.ErrorIs(t, verifySnapshotVoters(&raftpb.ConfState{Voters: []uint64{1, 2}, Learners: []uint64{3}}, block, 8), errSnapshotVoters)

	// Legacy ORDERER metadata is outside Fabric's block signature.
	unsigned := protoutil.NewBlock(1, nil)
	unsigned.Metadata.Metadata[cb.BlockMetadataIndex_ORDERER] = protoutil.MarshalOrPanic(&cb.Metadata{
		Value: protoutil.MarshalOrPanic(&etcdraft.BlockMetadata{RaftIndex: 8, ConsenterIds: []uint64{1, 2}}),
	})
	require.ErrorIs(t, verifySnapshotVoters(state, unsigned, 8), errSnapshotEvidence)
}

func TestPQ40DRestoredSnapshotConflictingLocalVoters(t *testing.T) {
	block := pq40dBoundaryBlock(8, 1, 2)
	block.Header.DataHash = protoutil.ComputeBlockDataHash(block.GetData())
	snapshot := &raftpb.Snapshot{
		Data: protoutil.MarshalOrPanic(block),
		Metadata: &raftpb.SnapshotMetadata{
			Index: new(uint64(8)), Term: new(uint64(1)),
			ConfState: &raftpb.ConfState{Voters: []uint64{1, 3}},
		},
	}
	support := &mocks.FakeConsenterSupport{}
	support.HeightReturns(2)
	support.BlockReturns(block)
	storage := raft.NewMemoryStorage()
	require.NoError(t, storage.ApplySnapshot(snapshot))
	require.NoError(t, storage.SetHardState(&raftpb.HardState{Commit: new(uint64(8)), Term: new(uint64(1))}))
	c := &Chain{support: support, opts: Options{MemoryStorage: storage}, Node: &node{storage: &RaftStorage{ram: storage}}}
	_, err := c.protectedSnapshotBlocks(snapshot, false)
	require.ErrorIs(t, err, errSnapshotEvidence, "remote mismatch is recoverable")
	err = c.validateRestoredRaft()
	require.ErrorIs(t, err, errSnapshotVoters, "local state conflicts at the same verified index")
	require.NotErrorIs(t, err, errSnapshotEvidence)
	require.Nil(t, c.stagedSnapshot)
}

func pq40dBoundaryBlock(index uint64, voters ...uint64) *cb.Block {
	block := protoutil.NewBlock(1, nil)
	block.Metadata.Metadata[cb.BlockMetadataIndex_SIGNATURES] = protoutil.MarshalOrPanic(&cb.Metadata{
		Signatures: []*cb.MetadataSignature{{Signature: []byte("fixture")}},
		Value: protoutil.MarshalOrPanic(&cb.OrdererBlockMetadata{
			ConsenterMetadata: protoutil.MarshalOrPanic(&cb.Metadata{
				Value: protoutil.MarshalOrPanic(&etcdraft.BlockMetadata{RaftIndex: index, ConsenterIds: voters}),
			}),
		}),
	})
	return block
}
