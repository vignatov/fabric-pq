//go:build linux

// SPDX-License-Identifier: Apache-2.0

package follower

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/hyperledger/fabric-lib-go/common/flogging"
	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation/testfixture"
	"github.com/hyperledger/fabric/orderer/common/types"
	"github.com/hyperledger/fabric/protoutil"
	"github.com/stretchr/testify/require"
)

type pq40dLedger struct {
	blocks []*cb.Block
}

func (l *pq40dLedger) Height() uint64                { return uint64(len(l.blocks)) }
func (l *pq40dLedger) ChannelID() string             { return testfixture.ChannelID }
func (l *pq40dLedger) Block(number uint64) *cb.Block { return l.blocks[number] }
func (l *pq40dLedger) Append(block *cb.Block) error {
	l.blocks = append(l.blocks, block)
	return nil
}

type pq40dPuller struct {
	ChannelPuller
	block *cb.Block
}

func (p pq40dPuller) PullBlock(uint64) *cb.Block { return p.block }

type pq40dVerifier struct {
	BlockPullerFactory
	block *cb.Block
}

func (v *pq40dVerifier) UpdateVerifierFromConfigBlock(block *cb.Block) error {
	v.block = block
	return nil
}

type pq40dMetrics struct{}

func (pq40dMetrics) ReportConsensusRelationAndStatusMetrics(string, types.ConsensusRelation, types.Status) {
}

func TestPQ40DParticipationAppend(t *testing.T) {
	for _, approved := range []bool{false, true} {
		t.Run(fmt.Sprintf("approved=%t", approved), func(t *testing.T) {
			root := t.TempDir()
			store, err := activation.OpenStore(root, nil)
			require.NoError(t, err)
			fixture := testfixture.New(t)
			genesis := testfixture.Genesis(t)
			base := testfixture.Config(t, genesis)
			fixture.Provision(t, store, base)
			update := fixture.Update(t, base)
			block := protoutil.NewBlock(1, protoutil.BlockHeaderHash(genesis.Header))
			block.Data = &cb.BlockData{Data: [][]byte{protoutil.MarshalOrPanic(fixture.Envelope(t, update))}}
			block.Header.DataHash = protoutil.ComputeBlockDataHash(block.Data)
			if approved {
				payload, err := json.Marshal(fixture.Authorize(t, 1, base, update.GetConfig()))
				require.NoError(t, err)
				id := sha256.Sum256([]byte(testfixture.ChannelID))
				require.NoError(t, os.WriteFile(filepath.Join(root, fmt.Sprintf("approval-%x-2", id)), payload, 0o600))
			}
			ledger := &pq40dLedger{blocks: []*cb.Block{genesis}}
			view := activation.Ledger{
				LatestConfig: func() (*cb.Block, error) { return ledger.blocks[len(ledger.blocks)-1], nil },
				Height:       func() (uint64, error) { return ledger.Height(), nil },
				Block:        func(number uint64) (*cb.Block, error) { return ledger.Block(number), nil },
				Sync:         func() error { return nil },
			}
			controller := fixture.Channel(store, view)
			require.NoError(t, controller.RecoverOrdererLedger())
			verifier := &pq40dVerifier{}
			chain := &Chain{
				options: Options{Activation: &controller}, stopChan: make(chan struct{}),
				ledgerResources: ledger, blockPuller: pq40dPuller{block: block}, blockPullerFactory: verifier,
				logger: flogging.MustGetLogger("pq40d.follower"), channelParticipationMetricsReporter: pq40dMetrics{},
			}
			count, err := chain.pullUntilTarget(2, false)
			if approved {
				require.NoError(t, err)
				require.Equal(t, uint64(1), count)
				require.Equal(t, uint64(2), ledger.Height())
				require.Same(t, block, verifier.block)
			} else {
				require.ErrorContains(t, err, "load operator approval")
				require.Zero(t, count)
				require.Equal(t, uint64(1), ledger.Height())
				require.Nil(t, verifier.block)
			}
			require.False(t, controller.Ready())
		})
	}
}
