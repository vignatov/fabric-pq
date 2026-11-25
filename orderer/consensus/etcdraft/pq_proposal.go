/*
SPDX-License-Identifier: Apache-2.0
*/

package etcdraft

import (
	"context"

	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation"
	"github.com/hyperledger/fabric/protoutil"
)

// queuedGeneration holds admission while work is parked. Closure can release
// this lease without waiting for the Raft application loop, which may itself
// be closing the gate. A consumer must acquire the same generation before
// touching resources or forwarding the work.
type queuedGeneration struct {
	context.Context
	release func()
}

func parkGeneration(gate *activation.Gate, expected context.Context) *queuedGeneration {
	_, generation, release, ok := gate.AcquireMatching(expected)
	if !ok {
		return nil
	}
	stop := context.AfterFunc(generation, release)
	return &queuedGeneration{Context: generation, release: func() {
		stop()
		release()
	}}
}

func (q *queuedGeneration) done() <-chan struct{} {
	if q == nil {
		return nil
	}
	return q.Done()
}

type raftProposal struct {
	block      *common.Block
	generation *queuedGeneration
}

func (c *Chain) proposeToRaft(leader context.Context, proposal raftProposal) error {
	if proposal.generation == nil {
		return c.Node.Propose(leader, protoutil.MarshalOrPanic(proposal.block))
	}
	parked := proposal.generation
	_, generation, release, ok := c.activation.Gate.AcquireMatching(parked.Context)
	parked.release()
	if !ok {
		return context.Canceled
	}
	defer release()
	ctx, cancel := context.WithCancel(leader)
	defer cancel()
	stop := context.AfterFunc(generation, cancel)
	defer stop()
	if err := generation.Err(); err != nil {
		return err
	}
	return c.Node.Propose(ctx, protoutil.MarshalOrPanic(proposal.block))
}
