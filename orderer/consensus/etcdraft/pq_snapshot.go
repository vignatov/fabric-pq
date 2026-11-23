// SPDX-License-Identifier: Apache-2.0

package etcdraft

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-protos-go-apiv2/orderer/etcdraft"
	"github.com/hyperledger/fabric/protoutil"
	"go.etcd.io/raft/v3"
	"go.etcd.io/raft/v3/raftpb"
	"google.golang.org/protobuf/proto"
)

const maxProtectedSnapshotBlocks = 1024

var errSnapshotEvidence = errors.New("protected snapshot evidence is incomplete")

type snapshotRequest struct {
	message *raftpb.Message
	result  chan error
}

type verifiedSnapshot struct {
	snapshot *raftpb.Snapshot
	blocks   []*common.Block
}

func (c *Chain) startProtected() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		err := c.validateRestoredRaft()
		if err == nil {
			c.start()
			return
		}
		if !errors.Is(err, errSnapshotEvidence) {
			c.failProtected(err)
			break
		}
		c.logger.Warningf("Waiting for protected Raft snapshot evidence: %s", err)
		select {
		case <-ticker.C:
			continue
		case <-c.haltC:
		}
		break
	}
	_ = c.Node.storage.Close()
	close(c.applicationDone)
	close(c.doneC)
}

func (c *Chain) validateRestoredRaft() error {
	state, _, err := c.opts.MemoryStorage.InitialState()
	if err != nil {
		return err
	}
	snapshot := c.Node.storage.Snapshot()
	last, err := c.opts.MemoryStorage.LastIndex()
	if err != nil {
		return err
	}
	if state.GetCommit() < snapshot.GetMetadata().GetIndex() || state.GetCommit() > last {
		return errors.New("Raft commit is outside the recovered log")
	}
	if raft.IsEmptySnap(snapshot) {
		return nil
	}
	blocks, err := c.protectedSnapshotBlocks(snapshot)
	if err == nil {
		c.stagedSnapshot = &verifiedSnapshot{snapshot: snapshot, blocks: blocks}
	}
	return err
}

func (c *Chain) authorizeIncomingSnapshot(message *raftpb.Message) error {
	req := snapshotRequest{message: message, result: make(chan error, 1)}
	select {
	case c.snapshotRequests <- req:
	case <-c.doneC:
		return ErrChainHalting
	}
	select {
	case err := <-req.result:
		return err
	case <-c.doneC:
		return ErrChainHalting
	}
}

func (c *Chain) stepProtectedSnapshot(message *raftpb.Message) error {
	status := c.Node.Status()
	snapshot := message.GetSnapshot()
	if raft.IsEmptySnap(snapshot) {
		return errSnapshotEvidence
	}
	if message.GetTerm() < status.GetTerm() || snapshot.GetMetadata().GetIndex() <= status.GetCommit() {
		return nil
	}
	c.activation.Suspend()
	c.snapshotPending = max(c.snapshotPending, snapshot.GetMetadata().GetIndex())
	blocks, err := c.protectedSnapshotBlocks(snapshot)
	if err != nil {
		if !errors.Is(err, errSnapshotEvidence) {
			c.failProtected(err)
		}
		return err
	}
	c.stagedSnapshot = &verifiedSnapshot{snapshot: snapshot, blocks: blocks}
	return c.Node.Step(context.Background(), message)
}

// protectedSnapshotBlocks authenticates the snapshot against durable local
// history or a bounded contiguous range of signed Fabric blocks.
func (c *Chain) protectedSnapshotBlocks(snapshot *raftpb.Snapshot) ([]*common.Block, error) {
	target, err := protoutil.UnmarshalBlock(snapshot.GetData())
	if err != nil || target.GetHeader() == nil ||
		!bytes.Equal(target.GetHeader().GetDataHash(), protoutil.ComputeBlockDataHash(target.GetData())) {
		return nil, fmt.Errorf("%w: invalid snapshot block", errSnapshotEvidence)
	}
	number := target.GetHeader().GetNumber()
	if syncer, ok := c.support.(interface{ WaitForBlockCommit() }); ok {
		syncer.WaitForBlockCommit()
	}
	height := c.support.Height()
	var blocks []*common.Block
	var last *common.Block
	if number < height {
		last = c.support.Block(number)
	} else {
		if height == 0 || number-height >= maxProtectedSnapshotBlocks {
			return nil, errSnapshotEvidence
		}
		puller, err := c.createPuller()
		if err != nil {
			return nil, fmt.Errorf("%w: %v", errSnapshotEvidence, err)
		}
		defer puller.Close()
		for sequence := height; sequence <= number; sequence++ {
			block := puller.PullBlock(sequence)
			if block == nil {
				return nil, fmt.Errorf("%w: missing block %d", errSnapshotEvidence, sequence)
			}
			blocks = append(blocks, block)
		}
		last = blocks[len(blocks)-1]
	}
	if !proto.Equal(last.GetHeader(), target.GetHeader()) || !proto.Equal(last.GetData(), target.GetData()) {
		return nil, fmt.Errorf("%w: snapshot conflicts with Fabric block %d", errSnapshotEvidence, number)
	}
	if len(blocks) > 0 {
		if err := c.activation.VerifyOrdererHistory(c.support.Block(height-1), blocks); err != nil {
			return nil, err
		}
	}
	if index := snapshot.GetMetadata().GetIndex(); index != 0 {
		if err := verifySnapshotVoters(snapshot.GetMetadata().GetConfState(), last, index); err != nil {
			return nil, err
		}
	}
	return blocks, nil
}

func verifySnapshotVoters(state *raftpb.ConfState, block *common.Block, index uint64) error {
	metadata, err := protoutil.GetConsenterMetadataFromBlock(block)
	if err != nil {
		return errSnapshotEvidence
	}
	config := &etcdraft.BlockMetadata{}
	if err := proto.Unmarshal(metadata.GetValue(), config); err != nil {
		return errSnapshotEvidence
	}
	expected := config.GetConsenterIds()
	if config.GetRaftIndex() == 0 || config.GetRaftIndex() > index || len(expected) == 0 ||
		!sameVoters(expected, state.GetVoters()) || len(state.GetLearners()) != 0 || len(state.GetVotersOutgoing()) != 0 ||
		len(state.GetLearnersNext()) != 0 || state.GetAutoLeave() {
		return fmt.Errorf("%w: snapshot voters do not match Fabric membership at its boundary", errSnapshotEvidence)
	}
	return nil
}

func (c *Chain) applyProtectedSnapshot(snapshot *raftpb.Snapshot) error {
	c.activation.Suspend()
	staged := c.stagedSnapshot
	var blocks []*common.Block
	if staged != nil && proto.Equal(staged.snapshot, snapshot) {
		c.stagedSnapshot = nil
		blocks = staged.blocks
		height := c.support.Height()
		for len(blocks) > 0 && blocks[0].GetHeader().GetNumber() < height {
			if !proto.Equal(c.support.Block(blocks[0].GetHeader().GetNumber()).GetHeader(), blocks[0].GetHeader()) {
				return errors.New("authorized snapshot history conflicts with the ledger")
			}
			blocks = blocks[1:]
		}
	} else {
		var err error
		blocks, err = c.protectedSnapshotBlocks(snapshot)
		if err != nil {
			return err
		}
	}
	for _, block := range blocks {
		if protoutil.IsConfigBlock(block) {
			if syncer, ok := c.support.(interface{ WaitForBlockCommit() }); ok {
				syncer.WaitForBlockCommit()
			}
			if err := c.checkOrderedMembership(block); err != nil {
				return err
			}
			if err := c.activation.ApplyOrdererConfig(block, func() error {
				c.commitBlock(block)
				return nil
			}); err != nil {
				return err
			}
		} else {
			c.commitBlock(block)
		}
		c.lastBlock = block
	}
	if syncer, ok := c.support.(interface{ WaitForBlockCommit() }); ok {
		syncer.WaitForBlockCommit()
	}
	if err := c.activation.Ledger.Sync(); err != nil {
		return err
	}
	index := snapshot.GetMetadata().GetIndex()
	if index > c.appliedIndex {
		c.confState = snapshot.GetMetadata().GetConfState()
		c.Node.confState.Store(c.confState)
		c.appliedIndex = index
	}
	if len(blocks) > 0 {
		metadata, err := blockRaftMetadata(c.lastBlock)
		if err != nil {
			return err
		}
		c.raftMetadataLock.Lock()
		c.opts.BlockMetadata = metadata
		c.raftMetadataLock.Unlock()
	}
	if index == 0 && !slices.Contains(c.opts.BlockMetadata.GetConsenterIds(), c.raftID) {
		go c.halt()
	}
	return c.publishAppliedComm()
}
