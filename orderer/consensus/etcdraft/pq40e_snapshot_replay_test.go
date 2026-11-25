/*
SPDX-License-Identifier: Apache-2.0
*/

package etcdraft

import (
	"testing"

	"github.com/hyperledger/fabric-lib-go/common/flogging"
	"github.com/hyperledger/fabric-lib-go/common/metrics/disabled"
	"github.com/hyperledger/fabric/protoutil"
	"github.com/stretchr/testify/require"
	"go.etcd.io/raft/v3/raftpb"
	"google.golang.org/protobuf/proto"
)

func TestPQ40EReplayedBlockDoesNotScheduleSnapshot(t *testing.T) {
	chain := &Chain{
		appliedIndex: 11, sizeLimit: 1, accDataSize: 1,
		gcC: make(chan *gc, 1), logger: flogging.MustGetLogger("pq40e.snapshot"),
		Metrics: NewMetrics(&disabled.Provider{}),
	}
	block := protoutil.NewBlock(1, nil)
	entry := &raftpb.Entry{Type: raftpb.EntryNormal.Enum(), Index: proto.Uint64(6), Data: protoutil.MarshalOrPanic(block)}
	require.NoError(t, chain.apply([]*raftpb.Entry{entry}))
	require.Equal(t, uint64(11), chain.appliedIndex)
	require.Equal(t, uint32(1+len(entry.GetData())), chain.accDataSize)
	require.Empty(t, chain.gcC, "replayed data must not schedule a snapshot at the ledger's newer index")
}
