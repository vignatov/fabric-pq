// SPDX-License-Identifier: Apache-2.0

package etcdraft

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"

	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-protos-go-apiv2/orderer/etcdraft"
	"github.com/hyperledger/fabric/common/channelconfig"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation"
	"github.com/hyperledger/fabric/orderer/common/types"
	"github.com/hyperledger/fabric/protoutil"
	"go.etcd.io/raft/v3"
	"go.etcd.io/raft/v3/raftpb"
	"google.golang.org/protobuf/proto"
)

type replayProgress struct {
	commit uint64
	read   uint64
	last   uint64
}

type replayBarrier struct {
	term      uint64
	leader    uint64
	commit    uint64
	index     uint64
	requestID []byte
	ticks     int
}

func (b *replayBarrier) changeEpoch(status raft.Status, channel *activation.Channel) {
	if b.term == status.GetTerm() && b.leader == status.Lead {
		return
	}
	b.term, b.leader = status.GetTerm(), status.Lead
	b.index, b.requestID, b.ticks = 0, nil, 0
	channel.Suspend()
}

func (b *replayBarrier) request(node raft.Node, status raft.Status, channel *activation.Channel) {
	b.changeEpoch(status, channel)
	if b.leader == raft.None || b.index != 0 {
		return
	}
	if b.requestID != nil && b.ticks < 5 {
		b.ticks++
		return
	}
	b.ticks = 0
	b.requestID = make([]byte, 32)
	_, _ = rand.Read(b.requestID)
	_ = node.ReadIndex(context.Background(), b.requestID)
}

func (b *replayBarrier) observe(ready raft.Ready, status raft.Status, channel *activation.Channel) {
	b.changeEpoch(status, channel)
	for _, state := range ready.ReadStates {
		if len(b.requestID) != 0 && bytes.Equal(state.RequestCtx, b.requestID) {
			b.index = state.Index
			b.requestID = nil
		}
	}
}

func containsConfiguration(entries []*raftpb.Entry) bool {
	for _, entry := range entries {
		if entry.GetType() != raftpb.EntryNormal {
			return true
		}
		if len(entry.GetData()) == 0 {
			continue
		}
		block, err := protoutil.UnmarshalBlock(entry.GetData())
		if err != nil || protoutil.IsConfigBlock(block) {
			return true
		}
	}
	return false
}

func (c *Chain) reconcileReplay(progress *replayProgress) error {
	if err := c.publishAppliedComm(); err != nil {
		return err
	}
	if c.activation.Ready() {
		return nil
	}
	// Wait for retained entries to commit or be replaced. A fresh join may
	// temporarily have a ledger index ahead of its local Raft storage.
	if progress.read == 0 || progress.commit < progress.read ||
		c.appliedIndex != progress.commit || progress.last != progress.commit ||
		progress.commit < c.snapshotPending ||
		c.configInflight || !sameVoters(c.confState.GetVoters(), c.opts.BlockMetadata.GetConsenterIds()) {
		return nil
	}
	c.snapshotPending = 0
	if syncer, ok := c.support.(interface{ WaitForBlockCommit() uint64 }); ok {
		syncer.WaitForBlockCommit()
	}
	if err := c.activation.Ledger.Sync(); err != nil {
		return err
	}
	if err := c.activation.CompleteOrdererReplay(); err != nil {
		return err
	}
	c.statusReportMutex.Lock()
	c.status = types.StatusActive
	c.statusReportMutex.Unlock()
	return nil
}

func (c *Chain) configureAppliedComm() error {
	if c.activation == nil {
		return c.configureComm()
	}
	c.commsPending = true
	return nil
}

func (c *Chain) publishAppliedComm() error {
	if !c.commsPending {
		return nil
	}
	if err := c.configureComm(); err != nil {
		return err
	}
	c.commsPending = false
	return nil
}

func sameVoters(first, second []uint64) bool {
	first, second = slices.Clone(first), slices.Clone(second)
	slices.Sort(first)
	slices.Sort(second)
	return slices.Equal(first, second)
}

// ValidateConfigForActivation checks deterministic Raft configuration
// constraints. Proposal-time quorum and certificate-freshness checks remain
// with the native configuration proposal path.
func ValidateConfigForActivation(conf channelconfig.Orderer) error {
	if conf.ConsensusType() != "etcdraft" {
		return errors.New("protected orderer activation requires etcdraft")
	}
	metadata := &etcdraft.ConfigMetadata{}
	if err := proto.Unmarshal(conf.ConsensusMetadata(), metadata); err != nil {
		return err
	}
	opts, err := createX509VerifyOptions(conf)
	if err != nil {
		return err
	}
	return VerifyConfigMetadata(metadata, opts)
}

func (c *Chain) failProtected(cause error) {
	c.protectedStopOnce.Do(func() {
		c.activation.Suspend()
		if !errors.Is(cause, activation.ErrNativeRecovery) {
			cause = c.activation.QuarantineOrderer(cause)
		}
		c.logger.Errorf("Protected channel stopped: %s", cause)
		c.statusReportMutex.Lock()
		c.status = types.StatusFailed
		c.statusReportMutex.Unlock()
		close(c.protectedStop)
	})
}

func (c *Chain) verifyReplayedBlock(block *common.Block, index uint64) error {
	committed := c.support.Block(block.GetHeader().GetNumber())
	if !proto.Equal(committed.GetHeader(), block.GetHeader()) || !proto.Equal(committed.GetData(), block.GetData()) {
		return fmt.Errorf("Raft entry at index %d conflicts with the durable Fabric block", index)
	}
	metadata, err := blockRaftMetadata(committed)
	if err != nil {
		return err
	}
	if metadata.GetRaftIndex() != index {
		return fmt.Errorf("Raft entry at index %d conflicts with durable block Raft index %d", index, metadata.GetRaftIndex())
	}
	return nil
}

func blockRaftMetadata(block *common.Block) (*etcdraft.BlockMetadata, error) {
	value, err := protoutil.GetConsenterMetadataFromBlock(block)
	if err != nil {
		return nil, err
	}
	metadata := &etcdraft.BlockMetadata{}
	return metadata, proto.Unmarshal(value.GetValue(), metadata)
}

func (c *Chain) checkOrderedMembership(block *common.Block) error {
	metadata, _, err := ConsensusMetadataFromConfigBlock(block)
	if err != nil {
		return err
	}
	if metadata == nil {
		return errors.New("missing ordered Raft config metadata")
	}
	_, err = ComputeMembershipChanges(c.opts.BlockMetadata, c.opts.Consenters, metadata.GetConsenters())
	return err
}

func (c *Chain) validateProtectedConfChange(change *raftpb.ConfChange, index uint64) error {
	ids := c.opts.BlockMetadata.GetConsenterIds()
	// Replayed membership entries can predate the current ledger config.
	// Use the authenticated Fabric block immediately preceding the entry.
	if index <= c.opts.BlockMetadata.GetRaftIndex() {
		for number := c.support.Height(); number > 0; number-- {
			block := c.support.Block(number - 1)
			if number == 1 {
				genesis, _, err := ConsensusMetadataFromConfigBlock(block)
				if err != nil {
					return err
				}
				ids = make([]uint64, len(genesis.GetConsenters()))
				for i := range ids {
					ids[i] = uint64(i + 1)
				}
				break
			}
			metadata, err := blockRaftMetadata(block)
			if err != nil {
				return err
			}
			if metadata.GetRaftIndex() < index {
				ids = metadata.GetConsenterIds()
				break
			}
		}
	}
	present := slices.Contains(c.confState.GetVoters(), change.GetNodeId())
	wanted := slices.Contains(ids, change.GetNodeId())
	switch change.GetType() {
	case raftpb.ConfChangeAddNode:
		if wanted || present {
			return nil
		}
	case raftpb.ConfChangeRemoveNode:
		if !wanted {
			return nil
		}
	}
	return fmt.Errorf("Raft membership change conflicts with authorized config: %s", change)
}
