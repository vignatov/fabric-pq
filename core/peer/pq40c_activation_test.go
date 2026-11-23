//go:build linux

/*
SPDX-License-Identifier: Apache-2.0
*/

package peer

import (
	"errors"
	"path/filepath"
	"testing"

	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	pb "github.com/hyperledger/fabric-protos-go-apiv2/peer"
	"github.com/hyperledger/fabric/common/channelconfig"
	"github.com/hyperledger/fabric/common/semaphore"
	"github.com/hyperledger/fabric/core/committer"
	validatorv20 "github.com/hyperledger/fabric/core/committer/txvalidator/v20"
	"github.com/hyperledger/fabric/core/ledger"
	"github.com/hyperledger/fabric/core/ledger/kvledger"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation/testfixture"
	mspmgmt "github.com/hyperledger/fabric/msp/mgmt"
	"github.com/hyperledger/fabric/protoutil"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestPQ40CPeerActivation(t *testing.T) {
	for _, scenario := range []string{"authorized", "missing operator", "missing Fabric signature", "committed without preparation", "mismatching join"} {
		t.Run(scenario, func(t *testing.T) {
			fixture := testfixture.New(t)
			genesis := testfixture.Genesis(t)
			base := testfixture.Config(t, genesis)
			update := fixture.Update(t, base)
			auth := fixture.Authorize(t, 1, base, update.GetConfig())
			if scenario == "missing Fabric signature" {
				update.LastUpdate = nil
			}
			if scenario == "missing operator" {
				auth = activation.Authorization{}
			}
			block := protoutil.NewBlock(1, protoutil.BlockHeaderHash(genesis.GetHeader()))
			block.Data.Data = [][]byte{protoutil.MarshalOrPanic(fixture.Envelope(t, update))}
			block.Header.DataHash = protoutil.ComputeBlockDataHash(block.GetData())
			block.Metadata.Metadata[cb.BlockMetadataIndex_LAST_CONFIG] = protoutil.MarshalOrPanic(&cb.Metadata{
				Value: protoutil.MarshalOrPanic(&cb.LastConfig{Index: 1}),
			})
			ledgerRoot := t.TempDir()
			manager, err := constructLedgerMgrWithTestDefaults(ledgerRoot)
			require.NoError(t, err)
			t.Cleanup(func() { manager.Close() })
			lgr, err := manager.CreateLedger(testfixture.ChannelID, genesis)
			require.NoError(t, err)
			store, err := activation.OpenStore(t.TempDir(), nil)
			require.NoError(t, err)
			if scenario == "mismatching join" {
				fixture.Provision(t, store, update.GetConfig())
			} else {
				fixture.Provision(t, store, base)
			}
			blockStore := kvledger.BlockStorePath(ledgerRoot)
			controller := fixture.Channel(store, activation.Ledger{
				LatestConfig: func() (*cb.Block, error) {
					committed, err := ConfigBlockFromLedger(lgr)
					if err != nil {
						return nil, err
					}
					worldState, err := RetrievePersistedChannelConfig(lgr)
					if err != nil {
						return nil, err
					}
					if !proto.Equal(worldState, testfixture.Config(t, committed)) {
						return nil, errors.New("world state conflicts with committed config block")
					}
					return committed, nil
				},
				Block: func(number uint64) (*cb.Block, error) { return lgr.GetBlockByNumber(number) },
				Height: func() (uint64, error) {
					info, err := lgr.GetBlockchainInfo()
					return info.GetHeight(), err
				},
				Sync: func() error {
					return activation.SyncDirectory(filepath.Join(blockStore, "chains", testfixture.ChannelID))
				},
			})
			var published []uint64
			var serving *channelconfig.BundleSource
			callback := func(bundle *channelconfig.Bundle) {
				_, _, _, admitted := controller.Gate.Acquire()
				require.False(t, admitted)
				published = append(published, bundle.ConfigtxValidator().Sequence())
			}
			controller.Publish = func(bundle *channelconfig.Bundle) error {
				if serving == nil {
					serving = channelconfig.NewBundleSource(bundle, callback, func(bundle *channelconfig.Bundle) {
						mspmgmt.XXXSetMSPManager(testfixture.ChannelID, bundle.MSPManager())
					})
				} else {
					serving.Update(bundle)
				}
				return nil
			}
			if scenario == "mismatching join" {
				require.ErrorContains(t, controller.Recover(true), "conflicts with protected checkpoint")
				require.Empty(t, published)
				return
			}
			require.NoError(t, controller.Recover(true))
			require.Equal(t, []uint64{0}, published)
			private := &Channel{cryptoProvider: fixture.Crypto}
			private.bundleSource = channelconfig.NewBundleSource(serving.StableBundle(), private.bundleUpdate)
			validator := &validatorv20.TxValidator{
				ChannelID: testfixture.ChannelID, Semaphore: semaphore.New(1), ChannelResources: private,
				LedgerResources: lgr, CryptoProvider: fixture.Crypto,
			}
			if scenario != "missing Fabric signature" {
				require.NoError(t, validator.Validate(block))
				require.Equal(t, byte(pb.TxValidationCode_VALID), block.GetMetadata().GetMetadata()[cb.BlockMetadataIndex_TRANSACTIONS_FILTER][0])
				require.Equal(t, uint64(1), private.Sequence())
				require.Equal(t, uint64(0), serving.ConfigtxValidator().Sequence())
			}
			commit := func() error {
				native := committer.NewLedgerCommitter(lgr, func(*cb.Block) {
					require.Equal(t, uint64(0), serving.ConfigtxValidator().Sequence())
				})
				return native.CommitLegacy(&ledger.BlockAndPvtData{Block: block}, &ledger.CommitOptions{})
			}
			switch scenario {
			case "authorized":
				require.NoError(t, controller.Apply(block, auth, commit))
				require.Equal(t, []uint64{0, 1}, published)
			case "missing operator":
				require.ErrorContains(t, controller.Apply(block, auth, commit), "operator authorization")
			case "missing Fabric signature":
				require.ErrorContains(t, controller.Apply(block, auth, commit), "Fabric config authorization")
			case "committed without preparation":
				require.NoError(t, commit())
			}
			lgr.Close()
			manager.Close()
			manager, err = constructLedgerMgrWithTestDefaults(ledgerRoot)
			require.NoError(t, err)
			lgr, err = manager.OpenLedger(testfixture.ChannelID)
			require.NoError(t, err)
			controller.Gate = &activation.Gate{}
			err = controller.Recover(true)
			if scenario == "missing operator" || scenario == "committed without preparation" {
				require.ErrorContains(t, err, "quarantined")
				require.ErrorContains(t, controller.Recover(true), "quarantined")
				require.Equal(t, []uint64{0}, published)
				return
			}
			require.NoError(t, err)
			bundle, _, release, admitted := controller.Gate.Acquire()
			require.True(t, admitted)
			defer release()
			want := uint64(0)
			if scenario == "authorized" {
				want = 1
			}
			require.Equal(t, want, bundle.ConfigtxValidator().Sequence())
		})
	}
}
