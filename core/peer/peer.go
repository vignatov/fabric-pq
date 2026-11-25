/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package peer

import (
	"context"
	"fmt"
	"sync"

	"github.com/hyperledger/fabric-lib-go/bccsp"
	"github.com/hyperledger/fabric-lib-go/common/flogging"
	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	pb "github.com/hyperledger/fabric-protos-go-apiv2/peer"
	"github.com/hyperledger/fabric/common/channelconfig"
	"github.com/hyperledger/fabric/common/deliver"
	"github.com/hyperledger/fabric/common/deliverclient/orderers"
	commonledger "github.com/hyperledger/fabric/common/ledger"
	"github.com/hyperledger/fabric/common/policies"
	"github.com/hyperledger/fabric/common/semaphore"
	"github.com/hyperledger/fabric/core/committer"
	"github.com/hyperledger/fabric/core/committer/txvalidator"
	"github.com/hyperledger/fabric/core/committer/txvalidator/plugin"
	validatorv14 "github.com/hyperledger/fabric/core/committer/txvalidator/v14"
	validatorv20 "github.com/hyperledger/fabric/core/committer/txvalidator/v20"
	"github.com/hyperledger/fabric/core/committer/txvalidator/v20/plugindispatcher"
	vir "github.com/hyperledger/fabric/core/committer/txvalidator/v20/valinforetriever"
	"github.com/hyperledger/fabric/core/common/privdata"
	validation "github.com/hyperledger/fabric/core/handlers/validation/api/state"
	"github.com/hyperledger/fabric/core/ledger"
	"github.com/hyperledger/fabric/core/ledger/ledgermgmt"
	"github.com/hyperledger/fabric/core/transientstore"
	"github.com/hyperledger/fabric/gossip/api"
	"github.com/hyperledger/fabric/gossip/protoext"
	gossipservice "github.com/hyperledger/fabric/gossip/service"
	"github.com/hyperledger/fabric/internal/pkg/comm"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/enrollment"
	"github.com/hyperledger/fabric/msp"
	mspmgmt "github.com/hyperledger/fabric/msp/mgmt"
	"github.com/hyperledger/fabric/protoutil"
	"github.com/pkg/errors"
)

var peerLogger = flogging.MustGetLogger("peer")

type CollectionInfoShim struct {
	plugindispatcher.CollectionAndLifecycleResources
	ChannelID string
}

func (cis *CollectionInfoShim) CollectionValidationInfo(chaincodeName, collectionName string, validationState validation.State) ([]byte, error, error) {
	return cis.CollectionAndLifecycleResources.CollectionValidationInfo(cis.ChannelID, chaincodeName, collectionName, validationState)
}

func ConfigBlockFromLedger(ledger ledger.PeerLedger) (*common.Block, error) {
	peerLogger.Debugf("Getting config block")

	// get last block.  Last block number is Height-1
	blockchainInfo, err := ledger.GetBlockchainInfo()
	if err != nil {
		return nil, err
	}
	lastBlock, err := ledger.GetBlockByNumber(blockchainInfo.GetHeight() - 1)
	if err != nil {
		return nil, err
	}

	// get most recent config block location from last block metadata
	configBlockIndex, err := protoutil.GetLastConfigIndexFromBlock(lastBlock)
	if err != nil {
		return nil, err
	}

	// get most recent config block
	configBlock, err := ledger.GetBlockByNumber(configBlockIndex)
	if err != nil {
		return nil, err
	}

	peerLogger.Debugf("Got config block[%d]", configBlockIndex)
	return configBlock, nil
}

// updates the trusted roots for the peer based on updates to channels
func (p *Peer) updateTrustedRoots(cm channelconfig.Resources) {
	if !p.ServerConfig.SecOpts.UseTLS {
		return
	}
	peerLogger.Debugf("Updating trusted root authorities for channel %s", cm.ConfigtxValidator().ChannelID())
	snapshot, err := comm.PrepareTrustedRootsForChain(cm)
	if err == nil {
		err = p.publishTrustedRoots(snapshot)
	}
	if err != nil {
		msg := "Failed to update trusted roots from latest config block. " +
			"This peer may not be able to communicate with members of channel %s (%s)"
		peerLogger.Warningf(msg, cm.ConfigtxValidator().ChannelID(), err)
	}
}

// publishTrustedRoots installs a prepared candidate. Protected channel owners
// must call it only after the corresponding checkpoint is durable.
func (p *Peer) publishTrustedRoots(snapshot *comm.TrustedRootsSnapshot) error {
	p.tlsRootsLock.Lock()
	defer p.tlsRootsLock.Unlock()
	publish, err := p.prepareTrustedRootsLocked(snapshot)
	if err != nil {
		return err
	}
	publish()
	return nil
}

func (p *Peer) prepareTrustedRootsLocked(snapshot *comm.TrustedRootsSnapshot) (func(), error) {
	trustedRoots, err := p.CredentialSupport.PreviewTrustedRootsForChain(snapshot)
	if err != nil {
		return nil, err
	}
	trustedRoots = append(trustedRoots, p.ServerConfig.SecOpts.ClientRootCAs...)
	trustedRoots = append(trustedRoots, p.ServerConfig.SecOpts.ServerRootCAs...)
	publishServer, err := p.server.PrepareClientRootCAs(trustedRoots)
	if err != nil {
		return nil, err
	}
	publishClient, err := p.CredentialSupport.PrepareTrustedRootsPublication(snapshot)
	if err != nil {
		return nil, err
	}
	return func() {
		publishServer()
		publishClient()
	}, nil
}

// ProtectedConfigPublication separates fallible retirement of old resources
// from installing the candidate. Retirement must be safe to retry and leave
// candidate state private. Publish must not fail.
type ProtectedConfigPublication struct {
	Retire  func() error
	Publish func()
}

// ProtectedConfigStage prepares a private resource candidate.
type ProtectedConfigStage func(*channelconfig.Bundle) (ProtectedConfigPublication, error)

// AddProtectedConfigStage registers an activation-owned resource publisher.
// Register stages before opening channels. Existing protected channels must be
// closed and recovered before the new consumer serves traffic.
func (p *Peer) AddProtectedConfigStage(stage ProtectedConfigStage) error {
	if stage == nil {
		return errors.New("protected resource stage is required")
	}
	p.protectedStagesLock.Lock()
	defer p.protectedStagesLock.Unlock()
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	if len(p.protectedCreating) != 0 {
		return errors.New("protected channel creation must finish before registering a resource stage")
	}
	for id, channel := range p.channels {
		if channel.activation != nil && channel.activation.Ready() {
			return errors.Errorf("protected channel %s must be closed before registering a resource stage", id)
		}
	}
	p.protectedConfigStages = append(p.protectedConfigStages, stage)
	return nil
}

// publishProtectedResources is called by an authenticated activation owner
// after durable commit, while channel admission is closed. On any error the
// owner must leave admission closed and retry publication during recovery.
func (p *Peer) publishProtectedResources(bundle *channelconfig.Bundle) error {
	release, err := p.beginProtectedPublication(bundle)
	if err != nil {
		return err
	}
	release()
	return nil
}

// beginProtectedPublication retains the registration barrier until the
// controller has either opened the new generation or abandoned publication.
func (p *Peer) beginProtectedPublication(bundle *channelconfig.Bundle) (func(), error) {
	p.protectedStagesLock.RLock()
	if err := p.publishProtectedResourcesLocked(bundle); err != nil {
		p.protectedStagesLock.RUnlock()
		return nil, err
	}
	return p.protectedStagesLock.RUnlock, nil
}

func (p *Peer) publishProtectedResourcesLocked(bundle *channelconfig.Bundle) error {
	var publishRoots func()
	if p.ServerConfig.SecOpts.UseTLS {
		roots, err := comm.PrepareTrustedRootsForChain(bundle)
		if err != nil {
			return err
		}
		p.tlsRootsLock.Lock()
		defer p.tlsRootsLock.Unlock()
		publishRoots, err = p.prepareTrustedRootsLocked(roots)
		if err != nil {
			return err
		}
	}
	staged := make([]ProtectedConfigPublication, 0, len(p.protectedConfigStages))
	for _, stage := range p.protectedConfigStages {
		publish, err := stage(bundle)
		if err != nil {
			return err
		}
		if publish.Publish == nil {
			return errors.New("protected resource stage returned no publisher")
		}
		staged = append(staged, publish)
	}
	for _, candidate := range staged {
		if candidate.Retire != nil {
			if err := candidate.Retire(); err != nil {
				return err
			}
		}
	}
	if publishRoots != nil {
		publishRoots()
	}
	for _, candidate := range staged {
		candidate.Publish()
	}
	return nil
}

//
//  Deliver service support structs for the peer
//

// DeliverChainManager provides access to a channel for performing deliver
type DeliverChainManager struct {
	Peer *Peer
}

func (d DeliverChainManager) GetChain(chainID string) deliver.Chain {
	if channel := d.Peer.Channel(chainID); channel != nil {
		return channel
	}
	return nil
}

// fileLedgerBlockStore implements the interface expected by
// common/ledger/blockledger/file to interact with a file ledger for deliver
type fileLedgerBlockStore struct {
	ledger.PeerLedger
}

func (flbs fileLedgerBlockStore) AddBlock(*common.Block) error {
	return nil
}

func (flbs fileLedgerBlockStore) RetrieveBlocks(startBlockNumber uint64) (commonledger.ResultsIterator, error) {
	return flbs.GetBlocksIterator(startBlockNumber)
}

func (flbs fileLedgerBlockStore) Shutdown() {}

// A Peer holds references to subsystems and channels associated with a Fabric peer.
type Peer struct {
	ServerConfig             comm.ServerConfig
	CredentialSupport        *comm.CredentialSupport
	StoreProvider            transientstore.StoreProvider
	GossipService            *gossipservice.GossipService
	LedgerMgr                *ledgermgmt.LedgerMgr
	OrdererEndpointOverrides map[string]*orderers.Endpoint
	CryptoProvider           bccsp.BCCSP
	// ProtectedRegistry must be installed by trusted startup before opening
	// channels, with the ledger manager using the manifest's ledger directory.
	ProtectedRegistry *enrollment.Registry

	// validationWorkersSemaphore is used to limit the number of concurrent validation
	// go routines.
	validationWorkersSemaphore semaphore.Semaphore

	server             *comm.GRPCServer
	pluginMapper       plugin.Mapper
	channelInitializer func(cid string)

	// channels is a map of channelID to channel
	mutex             sync.RWMutex
	channels          map[string]*Channel
	protectedCreating map[string]struct{}
	tlsRootsLock      sync.Mutex

	configCallbacks       []channelconfig.BundleActor
	protectedStagesLock   sync.RWMutex
	protectedConfigStages []ProtectedConfigStage
}

// AddConfigCallbacks adds one or more BundleActor functions to list of callbacks that
// get invoked when a channel configuration update event is received via gossip.
func (p *Peer) AddConfigCallbacks(callbacks ...channelconfig.BundleActor) {
	p.configCallbacks = append(p.configCallbacks, callbacks...)
}

func (p *Peer) openStore(cid string) (*transientstore.Store, error) {
	store, err := p.StoreProvider.OpenStore(cid)
	if err != nil {
		return nil, err
	}

	return store, nil
}

func (p *Peer) CreateChannel(
	cid string,
	cb *common.Block,
	deployedCCInfoProvider ledger.DeployedChaincodeInfoProvider,
	legacyLifecycleValidation plugindispatcher.LifecycleResources,
	newLifecycleValidation plugindispatcher.CollectionAndLifecycleResources,
) error {
	if p.ProtectedRegistry != nil {
		if controller := p.ProtectedRegistry.Controller(cid, p.CryptoProvider); controller != nil {
			controller.Validate = validateProtectedPeerConfig
			if err := controller.AuthorizeGenesis(cb); err != nil {
				return errors.Wrapf(err, "authorize protected genesis for %s", cid)
			}
		}
	}
	l, err := p.LedgerMgr.CreateLedger(cid, cb)
	if err != nil {
		return errors.WithMessage(err, "cannot create ledger from genesis block")
	}

	if err := p.createChannel(cid, l, deployedCCInfoProvider, legacyLifecycleValidation, newLifecycleValidation); err != nil {
		return err
	}

	p.initChannel(cid)
	return nil
}

// CreateChannelFromSnapshot creates a channel from the specified snapshot.
func (p *Peer) CreateChannelFromSnapshot(
	snapshotDir string,
	deployedCCInfoProvider ledger.DeployedChaincodeInfoProvider,
	legacyLifecycleValidation plugindispatcher.LifecycleResources,
	newLifecycleValidation plugindispatcher.CollectionAndLifecycleResources,
) error {
	var approvedChannel string
	cleanup := func() {}
	if p.ProtectedRegistry != nil {
		var err error
		approvedChannel, snapshotDir, cleanup, err = p.stageProtectedSnapshot(snapshotDir)
		if err != nil {
			return errors.Wrap(err, "authenticate protected snapshot")
		}
	}
	channelCallback := func(l ledger.PeerLedger, cid string) {
		if approvedChannel != "" && cid != approvedChannel {
			logger.Errorf("snapshot ledger %s conflicts with the authenticated channel %s", cid, approvedChannel)
			return
		}
		if err := p.createChannel(cid, l, deployedCCInfoProvider, legacyLifecycleValidation, newLifecycleValidation); err != nil {
			logger.Errorf("error creating channel for %s", cid)
			return
		}
		p.initChannel(cid)
	}

	err := p.LedgerMgr.CreateLedgerFromStagedSnapshot(snapshotDir, channelCallback, cleanup)
	if err != nil {
		cleanup()
		return errors.WithMessagef(err, "cannot create ledger from snapshot %s", snapshotDir)
	}

	return nil
}

// RetrievePersistedChannelConfig retrieves the persisted channel config from statedb
func RetrievePersistedChannelConfig(ledger ledger.PeerLedger) (*common.Config, error) {
	qe, err := ledger.NewQueryExecutor()
	if err != nil {
		return nil, err
	}
	defer qe.Done()
	return retrieveChannelConfig(qe)
}

// createChannel creates a new channel object and insert it into the channels slice.
func (p *Peer) createChannel(
	cid string,
	l ledger.PeerLedger,
	deployedCCInfoProvider ledger.DeployedChaincodeInfoProvider,
	legacyLifecycleValidation plugindispatcher.LifecycleResources,
	newLifecycleValidation plugindispatcher.CollectionAndLifecycleResources,
) error {
	controller, err := p.protectedController(cid, l)
	if err != nil {
		return errors.Wrap(err, "verify protected ledger provenance")
	}
	if controller != nil {
		p.mutex.Lock()
		_, creating := p.protectedCreating[cid]
		if creating || p.channels[cid] != nil {
			p.mutex.Unlock()
			return errors.Errorf("protected channel %s already exists or is being created", cid)
		}
		if p.protectedCreating == nil {
			p.protectedCreating = make(map[string]struct{})
		}
		p.protectedCreating[cid] = struct{}{}
		p.mutex.Unlock()
		defer func() {
			p.mutex.Lock()
			delete(p.protectedCreating, cid)
			p.mutex.Unlock()
		}()
		genesis, err := controller.Ledger.Block(0)
		if err != nil {
			return errors.Wrap(err, "load protected genesis")
		}
		if err := controller.VerifyGenesis(genesis); err != nil {
			return errors.Wrap(err, "verify protected genesis")
		}
	}
	chanConf, err := RetrievePersistedChannelConfig(l)
	if err != nil {
		return err
	}

	bundle, err := channelconfig.NewBundle(cid, chanConf, p.CryptoProvider)
	if err != nil {
		return err
	}

	if controller == nil {
		capabilitiesSupportedOrPanic(bundle)
		err = validateHybridLocalSigner(bundle)
	} else {
		err = validateProtectedPeerConfig(bundle)
	}
	if err != nil {
		return errors.Wrapf(err, "[channel %s] incompatible channel configuration", cid)
	}

	channelconfig.LogSanityChecks(bundle)

	if _, ok := bundle.OrdererConfig(); !ok {
		return errors.Errorf("[channel %s] cannot create channel because ChannelConfig is missing OrdererConfig", bundle.ConfigtxValidator().ChannelID())
	}

	gossipEventer := p.GossipService.NewConfigEventer()

	gossipCallbackWrapper := func(bundle *channelconfig.Bundle) {
		ac, ok := bundle.ApplicationConfig()
		if !ok {
			ac = nil
		}
		gossipEventer.ProcessConfigUpdate(gossipservice.ConfigUpdate{
			ChannelID:        bundle.ConfigtxValidator().ChannelID(),
			Organizations:    ac.Organizations(),
			OrdererAddresses: bundle.ChannelConfig().OrdererAddresses(),
			Sequence:         bundle.ConfigtxValidator().Sequence(),
		})
		p.GossipService.SuspectPeers(func(identity api.PeerIdentityType) bool {
			// TODO: this is a place-holder that would somehow make the MSP layer suspect
			// that a given certificate is revoked, or its intermediate CA is revoked.
			// In the meantime, before we have such an ability, we return true in order
			// to suspect ALL identities in order to validate all of them.
			return true
		})
	}

	trustedRootsCallbackWrapper := func(bundle *channelconfig.Bundle) {
		p.updateTrustedRoots(bundle)
	}

	mspCallback := func(bundle *channelconfig.Bundle) {
		// TODO remove once all references to mspmgmt are gone from peer code
		mspmgmt.XXXSetMSPManager(cid, bundle.MSPManager())
	}

	// Open the transient store before any callbacks publish channel resources.
	store, err := p.openStore(cid)
	if err != nil {
		return errors.Wrapf(err, "[channel %s] failed opening transient store", cid)
	}
	var channel, validationChannel *Channel
	var channelCommitter committer.Committer
	policyManager := p.GetPolicyManager
	if controller == nil {
		channel = &Channel{ledger: l, resources: bundle, cryptoProvider: p.CryptoProvider}
		callbacks := []channelconfig.BundleActor{
			gossipCallbackWrapper, trustedRootsCallbackWrapper, mspCallback, channel.bundleUpdate,
		}
		channel.bundleSource = channelconfig.NewBundleSource(bundle, append(callbacks, p.configCallbacks...)...)
		validationChannel = channel
		channelCommitter = committer.NewLedgerCommitter(l, func(block *common.Block) {
			if protoutil.IsConfigBlock(block) {
				channel.ValidateConfigActivation()
			}
		})
	} else {
		lifecycle, err := p.newProtectedLifecycle(controller, l, bundle, committer.NewLedgerCommitter(l, nil), mspCallback, gossipCallbackWrapper)
		if err != nil {
			return err
		}
		if err := lifecycle.recover(); err != nil {
			return errors.Wrap(err, "recover protected peer channel")
		}
		channel, validationChannel, channelCommitter = lifecycle.serving, lifecycle.validation, lifecycle.committer
		policyManager = func(id string) policies.Manager {
			if id == cid {
				return validationChannel.PolicyManager()
			}
			return p.GetPolicyManager(id)
		}
	}
	channel.store = store
	validationChannel.store = store

	validator := &txvalidator.ValidationRouter{
		CapabilityProvider: validationChannel,
		V14Validator: validatorv14.NewTxValidator(
			cid,
			p.validationWorkersSemaphore,
			validationChannel,
			p.pluginMapper,
			p.CryptoProvider,
		),
		V20Validator: validatorv20.NewTxValidator(
			cid,
			p.validationWorkersSemaphore,
			validationChannel,
			channel.Ledger(),
			&vir.ValidationInfoRetrieveShim{
				New:    newLifecycleValidation,
				Legacy: legacyLifecycleValidation,
			},
			&CollectionInfoShim{
				CollectionAndLifecycleResources: newLifecycleValidation,
				ChannelID:                       bundle.ConfigtxValidator().ChannelID(),
			},
			p.pluginMapper,
			policies.PolicyManagerGetterFunc(policyManager),
			p.CryptoProvider,
		),
	}

	var idDeserializerFactory privdata.IdentityDeserializerFactoryFunc = func(channelID string) msp.IdentityDeserializer {
		if channelID == cid {
			return channel.MSPManager()
		}
		return p.Channel(channelID).MSPManager()
	}
	simpleCollectionStore := privdata.NewSimpleCollectionStore(l, deployedCCInfoProvider, idDeserializerFactory)
	var gossipAdmission protoext.ChannelAdmission
	if controller != nil {
		gossipAdmission = func() (context.Context, func(), bool) {
			_, generation, release, admitted := controller.Gate.Acquire()
			return generation, release, admitted
		}
	}

	p.GossipService.InitializeChannel(
		bundle.ConfigtxValidator().ChannelID(),
		p.OrdererEndpointOverrides,
		store,
		gossipservice.Support{
			Validator:            validator,
			Committer:            channelCommitter,
			CollectionStore:      simpleCollectionStore,
			IdDeserializeFactory: idDeserializerFactory,
			CapabilityProvider:   channel,
			AcquireAdmission:     gossipAdmission,
		},
		chanConf,
		p.CryptoProvider,
	)

	p.mutex.Lock()
	defer p.mutex.Unlock()
	if p.channels == nil {
		p.channels = map[string]*Channel{}
	}
	p.channels[cid] = channel

	return nil
}

func (p *Peer) Channel(cid string) *Channel {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	if c, ok := p.channels[cid]; ok {
		return c
	}
	return nil
}

// AcquireChannelAdmission distinguishes unprotected channels from protected
// channels whose recovery has not yet made a serving generation available.
func (p *Peer) AcquireChannelAdmission(cid string) (context.Context, func(), bool) {
	if p.ProtectedRegistry == nil || !p.ProtectedRegistry.RequiresProtection(cid) {
		return nil, nil, true
	}
	channel := p.Channel(cid)
	if channel == nil || channel.activation == nil {
		return nil, nil, false
	}
	_, generation, release, ok := channel.activation.Gate.Acquire()
	return generation, release, ok
}

func (p *Peer) StoreForChannel(cid string) *transientstore.Store {
	if c := p.Channel(cid); c != nil {
		return c.Store()
	}
	return nil
}

// GetChannelsInfo returns an array with information about all channels for
// this peer.
func (p *Peer) GetChannelsInfo() []*pb.ChannelInfo {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	var channelInfos []*pb.ChannelInfo
	for key := range p.channels {
		ci := &pb.ChannelInfo{ChannelId: key}
		channelInfos = append(channelInfos, ci)
	}
	return channelInfos
}

// GetChannelConfig returns the channel configuration of the channel with channel ID. Note that this
// call returns nil if channel cid has not been created.
func (p *Peer) GetChannelConfig(cid string) channelconfig.Resources {
	if c := p.Channel(cid); c != nil {
		return c.Resources()
	}
	return nil
}

// GetStableChannelConfig returns the stable channel configuration of the channel with channel ID.
// Note that this call returns nil if channel cid has not been created.
func (p *Peer) GetStableChannelConfig(cid string) channelconfig.Resources {
	if c := p.Channel(cid); c != nil {
		return c.Resources()
	}
	return nil
}

// GetLedger returns the ledger of the channel with channel ID. Note that this
// call returns nil if channel cid has not been created.
func (p *Peer) GetLedger(cid string) ledger.PeerLedger {
	if c := p.Channel(cid); c != nil {
		return c.Ledger()
	}
	return nil
}

// GetMSPIDs returns the ID of each application MSP defined on this channel
func (p *Peer) GetMSPIDs(cid string) []string {
	if c := p.Channel(cid); c != nil {
		return c.GetMSPIDs()
	}
	return nil
}

// GetPolicyManager returns the policy manager of the channel with channel ID. Note that this
// call returns nil if channel cid has not been created.
func (p *Peer) GetPolicyManager(cid string) policies.Manager {
	if c := p.Channel(cid); c != nil {
		return c.Resources().PolicyManager()
	}
	return nil
}

// JoinBySnapshotStatus queries ledger mgr to get the status of joinbysnapshot
func (p *Peer) JoinBySnapshotStatus() *pb.JoinBySnapshotStatus {
	return p.LedgerMgr.JoinBySnapshotStatus()
}

// initChannel takes care to initialize channel after peer joined, for example deploys system CCs
func (p *Peer) initChannel(cid string) {
	if p.channelInitializer != nil {
		// Initialize chaincode, namely deploy system CC
		peerLogger.Debugf("Initializing channel %s", cid)
		p.channelInitializer(cid)
	}
}

func (p *Peer) GetApplicationConfig(cid string) (channelconfig.Application, bool) {
	cc := p.GetChannelConfig(cid)
	if cc == nil {
		return nil, false
	}

	return cc.ApplicationConfig()
}

// Initialize sets up any channels that the peer has from the persistence. This
// function should be called at the start up when the ledger and gossip
// ready
func (p *Peer) Initialize(
	init func(string),
	server *comm.GRPCServer,
	pm plugin.Mapper,
	deployedCCInfoProvider ledger.DeployedChaincodeInfoProvider,
	legacyLifecycleValidation plugindispatcher.LifecycleResources,
	newLifecycleValidation plugindispatcher.CollectionAndLifecycleResources,
	nWorkers int,
) {
	// TODO: exported dep fields or constructor
	p.server = server
	p.validationWorkersSemaphore = semaphore.New(nWorkers)
	p.pluginMapper = pm
	p.channelInitializer = init

	ledgerIds, err := p.LedgerMgr.GetLedgerIDs()
	if err != nil {
		panic(fmt.Errorf("error in initializing ledgermgmt: %w", err))
	}

	for _, cid := range ledgerIds {
		peerLogger.Infof("Loading chain %s", cid)
		ledger, err := p.LedgerMgr.OpenLedger(cid)
		if err != nil {
			peerLogger.Errorf("Failed to load ledger %s(%+v)", cid, err)
			peerLogger.Debugf("Error while loading ledger %s with message %s. We continue to the next ledger rather than abort.", cid, err)
			continue
		}
		// Create a chain if we get a valid ledger with config block
		err = p.createChannel(cid, ledger, deployedCCInfoProvider, legacyLifecycleValidation, newLifecycleValidation)
		if err != nil {
			peerLogger.Errorf("Failed to load chain %s(%s)", cid, err)
			peerLogger.Debugf("Error reloading chain %s with message %s. We continue to the next chain rather than abort.", cid, err)
			continue
		}

		p.initChannel(cid)
	}
}

func (flbs fileLedgerBlockStore) RetrieveBlockByNumber(blockNum uint64) (*common.Block, error) {
	return flbs.GetBlockByNumber(blockNum)
}
