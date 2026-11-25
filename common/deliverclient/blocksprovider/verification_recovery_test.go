/*
SPDX-License-Identifier: Apache-2.0
*/

package blocksprovider

import (
	"testing"

	"github.com/hyperledger/fabric-lib-go/common/flogging"
	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric/common/deliverclient/orderers"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation/testfixture"
	"github.com/hyperledger/fabric/protoutil"
	"github.com/stretchr/testify/require"
)

type committedBlocks struct {
	LedgerInfo
	blocks map[uint64]*cb.Block
}

func (l committedBlocks) GetBlocks(numbers []uint64) []*cb.Block {
	var blocks []*cb.Block
	for _, number := range numbers {
		if block := l.blocks[number]; block != nil {
			blocks = append(blocks, block)
		}
	}
	return blocks
}

func TestDeliveryVerifierRecoversCommittedGossipProgress(t *testing.T) {
	fixture := testfixture.New(t)
	genesis := testfixture.Genesis(t)
	tip := protoutil.NewBlock(6, nil)
	tip.Metadata.Metadata[cb.BlockMetadataIndex_LAST_CONFIG] = protoutil.MarshalOrPanic(&cb.Metadata{
		Value: protoutil.MarshalOrPanic(&cb.LastConfig{Index: 0}),
	})
	logger := flogging.MustGetLogger("test")
	ledger := committedBlocks{blocks: map[uint64]*cb.Block{0: genesis, 6: tip}}
	deliverer := &Deliverer{
		ChannelID: testfixture.ChannelID, Ledger: ledger, CryptoProvider: fixture.Crypto,
		Logger: logger, orderers: orderers.NewConnectionSource(logger, nil, ""),
		VerificationHeight: 1,
	}
	require.NoError(t, deliverer.refreshVerifier(7))
	require.EqualValues(t, 7, deliverer.VerificationHeight)
	require.ErrorContains(t, deliverer.UpdatableBlockVerifier.VerifyBlock(protoutil.NewBlock(1, nil)),
		"expected block number is [7]")
	require.ErrorContains(t, deliverer.refreshVerifier(8), "committed ledger tip is unavailable")
	require.EqualValues(t, 7, deliverer.VerificationHeight)
}
