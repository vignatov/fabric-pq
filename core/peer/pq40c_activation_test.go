//go:build linux

/*
SPDX-License-Identifier: Apache-2.0
*/

package peer

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	pb "github.com/hyperledger/fabric-protos-go-apiv2/peer"
	"github.com/hyperledger/fabric/common/channelconfig"
	"github.com/hyperledger/fabric/common/crypto/tlsgen"
	"github.com/hyperledger/fabric/common/semaphore"
	"github.com/hyperledger/fabric/core/committer"
	validatorv20 "github.com/hyperledger/fabric/core/committer/txvalidator/v20"
	"github.com/hyperledger/fabric/core/ledger"
	"github.com/hyperledger/fabric/core/ledger/kvledger"
	"github.com/hyperledger/fabric/internal/pkg/comm"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation/testfixture"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/enrollment"
	mspmgmt "github.com/hyperledger/fabric/msp/mgmt"
	"github.com/hyperledger/fabric/protoutil"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestPQ40ECreateChannelRecoversProtectedResources(t *testing.T) {
	fixture := testfixture.New(t)
	genesis := testfixture.Genesis(t)
	root := t.TempDir()
	state := t.TempDir()
	store, err := activation.OpenStore(state, nil)
	require.NoError(t, err)
	fixture.Provision(t, store, testfixture.Config(t, genesis))
	controller := fixture.Channel(store, activation.Ledger{})
	key := controller.Signer.Bytes()
	keyFile := filepath.Join(state, "policy-key")
	require.NoError(t, os.WriteFile(keyFile, key, 0o600))
	channelDigest := sha256.Sum256([]byte(testfixture.ChannelID))
	anchor, err := json.Marshal(hex.EncodeToString(protoutil.BlockHeaderHash(genesis.GetHeader())))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(state, "genesis-"+hex.EncodeToString(channelDigest[:])), anchor, 0o600))

	keyDigest := sha256.Sum256(key)
	registry, err := enrollment.OpenProtectedRegistry(&enrollment.Manifest{
		Mode: enrollment.Protected, Network: testfixture.Network, Node: testfixture.Node,
		Profile: pqtransport.ProfileV1, PolicySigner: keyFile, PolicySignerDigest: hex.EncodeToString(keyDigest[:]),
		StateDir: state, LedgerDir: filepath.Join(root, "ledgersData"),
	})
	require.NoError(t, err)
	p, cleanup := newTestPeer(t, root)
	t.Cleanup(cleanup)
	t.Cleanup(p.GossipService.Stop)
	p.ProtectedRegistry = registry
	p.Initialize(nil, nil, nil, nil, nil, nil, 1)

	badGenesis := proto.CloneOf(genesis)
	badGenesis.Header.DataHash = nil
	require.ErrorContains(t, p.CreateChannel(testfixture.ChannelID, badGenesis, nil, nil, nil), "authorize protected genesis")
	ids, err := p.LedgerMgr.GetLedgerIDs()
	require.NoError(t, err)
	require.Empty(t, ids)

	published := false
	require.NoError(t, p.AddProtectedConfigStage(func(bundle *channelconfig.Bundle) (ProtectedConfigPublication, error) {
		require.Equal(t, testfixture.ChannelID, bundle.ConfigtxValidator().ChannelID())
		return ProtectedConfigPublication{Publish: func() {
			require.Nil(t, p.Channel(testfixture.ChannelID))
			published = true
		}}, nil
	}))
	require.NoError(t, p.CreateChannel(testfixture.ChannelID, genesis, nil, nil, nil))
	require.True(t, published)
	channel := p.Channel(testfixture.ChannelID)
	require.NotNil(t, channel)
	require.NotNil(t, channel.activation)
	_, generation, release, ok := channel.AcquireEndorsement()
	require.True(t, ok)
	defer release()
	require.NotNil(t, generation.Done())
}

func TestPQ40CPeerActivation(t *testing.T) {
	testPeerActivation(t, false)
}

func TestPQ40B1PeerActivation(t *testing.T) {
	testPeerActivation(t, true)
}

func testPeerActivation(t *testing.T, transportCapability bool) {
	for _, scenario := range []string{"authorized", "staged authorized", "staged publish retry", "staged missing operator", "missing operator", "missing Fabric signature", "committed without preparation", "mismatching join"} {
		t.Run(scenario, func(t *testing.T) {
			fixture := testfixture.New(t)
			genesis := testfixture.Genesis(t)
			if transportCapability {
				genesis = testfixture.TransportGenesis(t)
			}
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
			stateDir := t.TempDir()
			store, err := activation.OpenStore(stateDir, nil)
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
			var tlsPublished []uint64
			var tlsPeer *Peer
			failPublish := scenario == "staged publish retry"
			if scenario == "staged authorized" || failPublish {
				ca, err := tlsgen.NewCA()
				require.NoError(t, err)
				pair, err := ca.NewServerCertKeyPair("127.0.0.1")
				require.NoError(t, err)
				config := comm.ServerConfig{SecOpts: comm.SecureOptions{UseTLS: true, Certificate: pair.Cert, Key: pair.Key}}
				server, err := comm.NewGRPCServer("127.0.0.1:0", config)
				require.NoError(t, err)
				t.Cleanup(func() { _ = server.Listener().Close() })
				tlsPeer = &Peer{ServerConfig: config, CredentialSupport: comm.NewCredentialSupport(), server: server}
				require.NoError(t, tlsPeer.AddProtectedConfigStage(func(bundle *channelconfig.Bundle) (ProtectedConfigPublication, error) {
					return ProtectedConfigPublication{
						Retire: func() error {
							if failPublish && bundle.ConfigtxValidator().Sequence() == 1 {
								failPublish = false
								return errors.New("injected cache retirement failure")
							}
							return nil
						},
						Publish: func() { tlsPublished = append(tlsPublished, bundle.ConfigtxValidator().Sequence()) },
					}, nil
				}))
			}
			var serving *channelconfig.BundleSource
			callback := func(bundle *channelconfig.Bundle) {
				_, _, _, admitted := controller.Gate.Acquire()
				require.False(t, admitted)
				published = append(published, bundle.ConfigtxValidator().Sequence())
			}
			controller.Publish = func(bundle *channelconfig.Bundle) error {
				if tlsPeer != nil {
					if err := tlsPeer.publishProtectedResources(bundle); err != nil {
						return err
					}
				}
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
					if tlsPeer != nil {
						require.Equal(t, []uint64{0}, tlsPublished, "TLS roots changed before native commit completed")
					}
				})
				return native.CommitLegacy(&ledger.BlockAndPvtData{Block: block}, &ledger.CommitOptions{})
			}
			switch scenario {
			case "authorized":
				require.NoError(t, controller.Apply(block, auth, commit))
				require.Equal(t, []uint64{0, 1}, published)
			case "staged authorized", "staged publish retry", "staged missing operator":
				if scenario != "staged missing operator" {
					encoded, err := json.Marshal(auth)
					require.NoError(t, err)
					id := sha256.Sum256([]byte(testfixture.ChannelID))
					require.NoError(t, os.WriteFile(filepath.Join(stateDir, fmt.Sprintf("approval-%x-2", id)), encoded, 0o600))
				}
				native := committer.NewLedgerCommitter(lgr, func(*cb.Block) {
					require.Equal(t, uint64(0), serving.ConfigtxValidator().Sequence())
					if tlsPeer != nil {
						require.Equal(t, []uint64{0}, tlsPublished, "TLS and cache changed before native commit completed")
					}
				})
				guarded := &protectedCommitter{Committer: native, controller: &controller}
				err := guarded.CommitLegacy(&ledger.BlockAndPvtData{Block: block}, &ledger.CommitOptions{})
				if scenario == "staged publish retry" {
					require.ErrorContains(t, err, "injected cache retirement failure")
					require.False(t, controller.Ready())
					require.Equal(t, []uint64{0}, published)
					require.Equal(t, []uint64{0}, tlsPublished)
					require.NoError(t, controller.Recover(true))
				}
				if scenario != "staged missing operator" {
					if scenario == "staged publish retry" {
						err = nil
					}
					require.NoError(t, err)
					require.Equal(t, []uint64{0, 1}, published)
					require.Equal(t, []uint64{0, 1}, tlsPublished)
					require.NotEmpty(t, tlsPeer.CredentialSupport.AppRootCAsByChain())
				} else {
					require.ErrorContains(t, err, "load operator approval")
				}
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
			if scenario == "missing operator" || scenario == "staged missing operator" || scenario == "committed without preparation" {
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
			if scenario == "authorized" || scenario == "staged authorized" || scenario == "staged publish retry" {
				want = 1
			}
			require.Equal(t, want, bundle.ConfigtxValidator().Sequence())
		})
	}
}

type blockingPeerCommitter struct {
	committer.Committer
	started chan struct{}
	finish  chan struct{}
}

func (c *blockingPeerCommitter) CommitLegacy(*ledger.BlockAndPvtData, *ledger.CommitOptions) error {
	close(c.started)
	<-c.finish
	return nil
}

func TestPQ40EProtectedPeerCommitDrainsGeneration(t *testing.T) {
	fixture := testfixture.New(t)
	genesis := testfixture.Genesis(t)
	store, err := activation.OpenStore(t.TempDir(), nil)
	require.NoError(t, err)
	fixture.Provision(t, store, testfixture.Config(t, genesis))
	controller := fixture.Channel(store, activation.Ledger{
		LatestConfig: func() (*cb.Block, error) { return genesis, nil },
		Block: func(number uint64) (*cb.Block, error) {
			if number != 0 {
				return nil, errors.New("missing block")
			}
			return genesis, nil
		},
		Height: func() (uint64, error) { return 1, nil },
		Sync:   func() error { return nil },
	})
	require.NoError(t, controller.Recover(true))
	channel := &Channel{activation: &controller}
	peer := &Peer{channels: map[string]*Channel{testfixture.ChannelID: channel}}
	stage := func(*channelconfig.Bundle) (ProtectedConfigPublication, error) {
		return ProtectedConfigPublication{Publish: func() {}}, nil
	}
	require.ErrorContains(t, peer.AddProtectedConfigStage(stage), "must be closed")
	require.Empty(t, peer.protectedConfigStages)
	deserializer, generation, release, admitted := channel.AcquireEndorsement()
	require.True(t, admitted)
	require.NotNil(t, deserializer)
	require.NoError(t, generation.Err())
	release()
	envelope, err := protoutil.CreateSignedEnvelope(cb.HeaderType_ENDORSER_TRANSACTION, testfixture.ChannelID, nil, &cb.Config{}, 0, 0)
	require.NoError(t, err)
	block := protoutil.NewBlock(1, protoutil.BlockHeaderHash(genesis.GetHeader()))
	block.Data.Data = [][]byte{protoutil.MarshalOrPanic(envelope)}
	block.Header.DataHash = protoutil.ComputeBlockDataHash(block.GetData())
	native := &blockingPeerCommitter{started: make(chan struct{}), finish: make(chan struct{})}
	guarded := &protectedCommitter{Committer: native, controller: &controller}
	done := make(chan error, 1)
	go func() { done <- guarded.CommitLegacy(&ledger.BlockAndPvtData{Block: block}, &ledger.CommitOptions{}) }()
	select {
	case <-native.started:
	case <-time.After(5 * time.Second):
		t.Fatal("native commit did not start")
	}
	drained := make(chan struct{})
	go func() { controller.Suspend(); close(drained) }()
	<-controller.Gate.Errored()
	select {
	case <-drained:
		t.Fatal("generation drained before native commit finished")
	default:
	}
	close(native.finish)
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("native commit did not finish")
	}
	select {
	case <-drained:
	case <-time.After(5 * time.Second):
		t.Fatal("generation did not drain")
	}
	_, _, _, admitted = channel.AcquireEndorsement()
	require.False(t, admitted)
	require.NoError(t, peer.AddProtectedConfigStage(stage))
	require.ErrorContains(t, guarded.CommitLegacy(&ledger.BlockAndPvtData{Block: block}, &ledger.CommitOptions{}), "admission is closed")
}

func TestPQ40EProtectedLifecycleUsesPrivateValidationAndPublishedResources(t *testing.T) {
	fixture := testfixture.New(t)
	genesis := testfixture.Genesis(t)
	base := testfixture.Config(t, genesis)
	update := fixture.Update(t, base)
	block := protoutil.NewBlock(1, protoutil.BlockHeaderHash(genesis.GetHeader()))
	block.Data.Data = [][]byte{protoutil.MarshalOrPanic(fixture.Envelope(t, update))}
	block.Header.DataHash = protoutil.ComputeBlockDataHash(block.GetData())
	block.Metadata.Metadata[cb.BlockMetadataIndex_LAST_CONFIG] = protoutil.MarshalOrPanic(&cb.Metadata{
		Value: protoutil.MarshalOrPanic(&cb.LastConfig{Index: 1}),
	})
	root := t.TempDir()
	manager, err := constructLedgerMgrWithTestDefaults(root)
	require.NoError(t, err)
	t.Cleanup(func() { manager.Close() })
	lgr, err := manager.CreateLedger(testfixture.ChannelID, genesis)
	require.NoError(t, err)
	stateDir := t.TempDir()
	store, err := activation.OpenStore(stateDir, nil)
	require.NoError(t, err)
	fixture.Provision(t, store, base)
	controller := fixture.Channel(store, activation.Ledger{
		LatestConfig: func() (*cb.Block, error) { return ConfigBlockFromLedger(lgr) },
		Block:        func(number uint64) (*cb.Block, error) { return lgr.GetBlockByNumber(number) },
		Height:       func() (uint64, error) { info, err := lgr.GetBlockchainInfo(); return info.GetHeight(), err },
		Sync: func() error {
			return activation.SyncDirectory(filepath.Join(kvledger.BlockStorePath(root), "chains", testfixture.ChannelID))
		},
	})
	require.ErrorContains(t, controller.RecoverPeer(), "publisher is not installed")
	require.False(t, controller.Ready())
	initial, err := channelconfig.NewBundle(testfixture.ChannelID, base, fixture.Crypto)
	require.NoError(t, err)
	peer := &Peer{CryptoProvider: fixture.Crypto}
	var resources []uint64
	failPublication := true
	require.NoError(t, peer.AddProtectedConfigStage(func(bundle *channelconfig.Bundle) (ProtectedConfigPublication, error) {
		return ProtectedConfigPublication{
			Retire: func() error {
				if failPublication && bundle.ConfigtxValidator().Sequence() == 1 {
					failPublication = false
					return errors.New("injected protected resource failure")
				}
				return nil
			},
			Publish: func() { resources = append(resources, bundle.ConfigtxValidator().Sequence()) },
		}, nil
	}))
	var lifecycle *protectedLifecycle
	native := committer.NewLedgerCommitter(lgr, func(*cb.Block) {
		require.Equal(t, uint64(0), lifecycle.serving.Sequence())
		require.Equal(t, []uint64{0, 0}, resources)
	})
	var published []uint64
	firstPublication := true
	publicationEntered := make(chan struct{})
	publicationContinue := make(chan struct{})
	continuePublication := sync.OnceFunc(func() { close(publicationContinue) })
	defer continuePublication()
	lifecycle, err = peer.newProtectedLifecycle(&controller, lgr, initial, native, func(bundle *channelconfig.Bundle) {
		_, _, release, admitted := controller.Gate.Acquire()
		if admitted {
			release()
			t.Error("publication ran while admission was open")
		}
		if firstPublication {
			firstPublication = false
			close(publicationEntered)
			<-publicationContinue
		}
		mspmgmt.XXXSetMSPManager(testfixture.ChannelID, bundle.MSPManager())
		published = append(published, bundle.ConfigtxValidator().Sequence())
	})
	require.NoError(t, err)
	require.Nil(t, lifecycle.serving.Resources())
	require.Empty(t, resources)
	peer.channels = map[string]*Channel{testfixture.ChannelID: lifecycle.serving}
	recovered := make(chan error, 1)
	go func() { recovered <- lifecycle.recover() }()
	select {
	case <-publicationEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("publication did not start")
	}
	registrationStarted := make(chan struct{})
	registered := make(chan error, 1)
	go func() {
		close(registrationStarted)
		registered <- peer.AddProtectedConfigStage(func(*channelconfig.Bundle) (ProtectedConfigPublication, error) {
			return ProtectedConfigPublication{Publish: func() {}}, nil
		})
	}()
	<-registrationStarted
	select {
	case <-registered:
		t.Fatal("resource registration crossed an unfinished publication")
	case <-time.After(50 * time.Millisecond):
	}
	continuePublication()
	select {
	case err := <-recovered:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("recovery did not finish")
	}
	select {
	case err := <-registered:
		require.ErrorContains(t, err, "must be closed")
	case <-time.After(5 * time.Second):
		t.Fatal("resource registration did not finish")
	}
	require.Equal(t, []uint64{0}, published)
	require.ErrorContains(t, controller.InstallPublisher(func(*channelconfig.Bundle) error { return nil }), "before admission opens")
	validator := &validatorv20.TxValidator{
		ChannelID: testfixture.ChannelID, Semaphore: semaphore.New(1), ChannelResources: lifecycle.validation,
		LedgerResources: lgr, CryptoProvider: fixture.Crypto,
	}
	require.NoError(t, validator.Validate(block))
	require.Equal(t, byte(pb.TxValidationCode_VALID), block.GetMetadata().GetMetadata()[cb.BlockMetadataIndex_TRANSACTIONS_FILTER][0])
	require.Equal(t, uint64(1), lifecycle.validation.Sequence())
	require.Equal(t, uint64(0), lifecycle.serving.Sequence())
	invalidUpdate := proto.Clone(update).(*cb.ConfigEnvelope)
	invalidUpdate.LastUpdate = nil
	invalidBlock := proto.Clone(block).(*cb.Block)
	invalidBlock.Data.Data = [][]byte{protoutil.MarshalOrPanic(fixture.Envelope(t, invalidUpdate))}
	invalidBlock.Header.DataHash = protoutil.ComputeBlockDataHash(invalidBlock.GetData())
	err = lifecycle.committer.CommitLegacy(&ledger.BlockAndPvtData{Block: invalidBlock}, &ledger.CommitOptions{})
	require.ErrorContains(t, err, "Fabric config authorization")
	require.False(t, controller.Ready())
	require.Equal(t, uint64(1), lifecycle.validation.Sequence())
	require.NoError(t, lifecycle.recover())
	require.Equal(t, uint64(0), lifecycle.validation.Sequence())
	require.Equal(t, uint64(0), lifecycle.serving.Sequence())
	require.NoError(t, validator.Validate(block))
	require.Equal(t, uint64(1), lifecycle.validation.Sequence())
	auth, err := json.Marshal(fixture.Authorize(t, 1, base, update.GetConfig()))
	require.NoError(t, err)
	id := sha256.Sum256([]byte(testfixture.ChannelID))
	require.NoError(t, os.WriteFile(filepath.Join(stateDir, fmt.Sprintf("approval-%x-2", id)), auth, 0o600))
	err = lifecycle.committer.CommitLegacy(&ledger.BlockAndPvtData{Block: block}, &ledger.CommitOptions{})
	require.ErrorContains(t, err, "injected protected resource failure")
	require.False(t, controller.Ready())
	require.Equal(t, uint64(0), lifecycle.serving.Sequence())
	require.Equal(t, []uint64{0, 0}, resources)
	require.NoError(t, lifecycle.recover())
	require.Equal(t, uint64(1), lifecycle.serving.Sequence())
	require.Equal(t, []uint64{0, 0, 1}, published)
	require.Equal(t, []uint64{0, 0, 1}, resources)
	controller.Suspend()
	lgr.Close()
	manager.Close()
	manager, err = constructLedgerMgrWithTestDefaults(root)
	require.NoError(t, err)
	lgr, err = manager.OpenLedger(testfixture.ChannelID)
	require.NoError(t, err)
	controller = fixture.Channel(store, controller.Ledger)
	restoredConfig, err := RetrievePersistedChannelConfig(lgr)
	require.NoError(t, err)
	restoredBundle, err := channelconfig.NewBundle(testfixture.ChannelID, restoredConfig, fixture.Crypto)
	require.NoError(t, err)
	restoredPeer := &Peer{CryptoProvider: fixture.Crypto}
	var restoredResources []uint64
	require.NoError(t, restoredPeer.AddProtectedConfigStage(func(bundle *channelconfig.Bundle) (ProtectedConfigPublication, error) {
		return ProtectedConfigPublication{Publish: func() {
			restoredResources = append(restoredResources, bundle.ConfigtxValidator().Sequence())
		}}, nil
	}))
	restored, err := restoredPeer.newProtectedLifecycle(&controller, lgr, restoredBundle, committer.NewLedgerCommitter(lgr, nil))
	require.NoError(t, err)
	require.Nil(t, restored.serving.Resources())
	require.NoError(t, restored.recover())
	require.Equal(t, uint64(1), restored.serving.Sequence())
	require.Equal(t, []uint64{1}, restoredResources)
	require.Equal(t, []uint64{0, 0, 1}, resources)
}
