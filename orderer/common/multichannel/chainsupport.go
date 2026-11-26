/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package multichannel

import (
	"context"

	"github.com/hyperledger/fabric-lib-go/bccsp"
	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric/common/ledger/blockledger"
	"github.com/hyperledger/fabric/internal/pkg/identity"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation"
	"github.com/hyperledger/fabric/orderer/common/blockcutter"
	"github.com/hyperledger/fabric/orderer/common/msgprocessor"
	"github.com/hyperledger/fabric/orderer/common/types"
	"github.com/hyperledger/fabric/orderer/consensus"
	"github.com/hyperledger/fabric/protoutil"
	"github.com/pkg/errors"
)

// ChainSupport holds the resources for a particular channel.
type ChainSupport struct {
	activation *activation.Channel
	*ledgerResources
	msgprocessor.Processor
	*BlockWriter
	consensus.Chain
	cutter blockcutter.Receiver
	identity.SignerSerializer
	BCCSP bccsp.BCCSP

	// NOTE: It makes sense to add this to the ChainSupport since the design of Registrar does not assume
	// that there is a single consensus type at this orderer node and therefore the resolution of
	// the consensus type too happens only at the ChainSupport level.
	consensus.MetadataValidator

	// The registrar is not aware of the exact type that the Chain is, e.g. etcdraft, inactive, or follower.
	// Therefore, we let each chain report its cluster relation and status through this interface. Non cluster
	// type chains (solo) are assigned a static reporter.
	consensus.StatusReporter
}

func (cs *ChainSupport) OrdererActivation() *activation.Channel {
	return cs.activation
}

func (cs *ChainSupport) AdmissionReady() bool {
	return cs.activation == nil || cs.activation.Ready()
}

// AcquireBroadcastAdmission binds validation and the cancellable consensus
// handoff to the currently approved generation.
func (cs *ChainSupport) AcquireBroadcastAdmission() (context.Context, func(), bool) {
	if cs.activation == nil {
		return nil, func() {}, true
	}
	_, ctx, release, ok := cs.activation.Gate.Acquire()
	return ctx, release, ok
}

// OrderWithGeneration refuses a protected handoff unless the consenter can
// keep the validated generation attached to the submission.
func (cs *ChainSupport) OrderWithGeneration(generation context.Context, env *cb.Envelope, seq uint64) error {
	guarded, ok := cs.Chain.(interface {
		OrderWithGeneration(context.Context, *cb.Envelope, uint64) error
	})
	if !ok {
		return errors.New("consenter does not support protected order handoff")
	}
	return guarded.OrderWithGeneration(generation, env, seq)
}

// ConfigureWithGeneration applies the same handoff requirement to config
// updates, which may themselves initiate a generation transition.
func (cs *ChainSupport) ConfigureWithGeneration(generation context.Context, env *cb.Envelope, seq uint64) error {
	guarded, ok := cs.Chain.(interface {
		ConfigureWithGeneration(context.Context, *cb.Envelope, uint64) error
	})
	if !ok {
		return errors.New("consenter does not support protected config handoff")
	}
	return guarded.ConfigureWithGeneration(generation, env, seq)
}

// WaitReadyWithGeneration prevents protected readiness waits from spanning a
// generation transition. Protected consenters must implement this boundary.
func (cs *ChainSupport) WaitReadyWithGeneration(generation context.Context) error {
	if guarded, ok := cs.Chain.(interface{ WaitReadyWithGeneration(context.Context) error }); ok {
		return guarded.WaitReadyWithGeneration(generation)
	}
	if cs.activation != nil {
		return errors.New("consenter does not support protected readiness")
	}
	return cs.WaitReady()
}

func (cs *ChainSupport) AcquireDeliveryAdmission() (context.Context, func(), bool) {
	return cs.AcquireBroadcastAdmission()
}

func (cs *ChainSupport) RequiredDeliveryAdmission() <-chan struct{} {
	if cs.activation == nil {
		return nil
	}
	return cs.activation.Gate.Errored()
}

func newChainSupport(
	registrar *Registrar,
	ledgerResources *ledgerResources,
	consenters map[string]consensus.Consenter,
	signer identity.SignerSerializer,
	blockcutterMetrics *blockcutter.Metrics,
	bccsp bccsp.BCCSP,
) (*ChainSupport, error) {
	// Read in the last block and metadata for the channel
	lastBlock := blockledger.GetBlock(ledgerResources, ledgerResources.Height()-1)
	metadata, err := protoutil.GetConsenterMetadataFromBlock(lastBlock)
	// Assuming a block created with cb.NewBlock(), this should not
	// error even if the orderer metadata is an empty byte slice
	if err != nil {
		return nil, errors.WithMessagef(err, "error extracting orderer metadata for channel: %s", ledgerResources.ConfigtxValidator().ChannelID())
	}

	// Construct limited support needed as a parameter for additional support
	cs := &ChainSupport{
		ledgerResources:  ledgerResources,
		SignerSerializer: signer,
		cutter: blockcutter.NewReceiverImpl(
			ledgerResources.ConfigtxValidator().ChannelID(),
			ledgerResources,
			blockcutterMetrics,
		),
		BCCSP: bccsp,
	}

	// Set up the msgprocessor
	cs.Processor = msgprocessor.NewStandardChannel(cs, msgprocessor.CreateStandardChannelFilters(cs, registrar.config), bccsp)

	// Set up the block writer
	cs.BlockWriter = newBlockWriter(lastBlock, cs)
	cs.activation = registrar.activationFor(ledgerResources)
	if cs.activation != nil {
		if err := cs.activation.VerifyGenesis(ledgerResources.Block(0)); err != nil {
			return nil, cs.activation.QuarantineOrderer(err)
		}
		if err := cs.activation.RecoverOrdererLedger(); err != nil {
			return nil, err
		}
	}

	// Set up the consenter
	consenterType := ledgerResources.SharedConfig().ConsensusType()
	consenter, ok := consenters[consenterType]
	if !ok {
		return nil, errors.Errorf("error retrieving consenter of type: %s", consenterType)
	}

	cs.Chain, err = consenter.HandleChain(cs, metadata)
	if err != nil {
		return nil, errors.WithMessagef(err, "error creating consenter for channel: %s", cs.ChannelID())
	}

	cs.MetadataValidator, ok = cs.Chain.(consensus.MetadataValidator)
	if !ok {
		return nil, errors.Errorf("consenter of type %s for channel %s does not validate consensus metadata", consenterType, cs.ChannelID())
	}

	cs.StatusReporter, ok = cs.Chain.(consensus.StatusReporter)
	if !ok { // Non-cluster types: solo
		cs.StatusReporter = consensus.StaticStatusReporter{ConsensusRelation: types.ConsensusRelationOther, Status: types.StatusActive}
	}

	clusterRelation, status := cs.StatusReport()
	registrar.ReportConsensusRelationAndStatusMetrics(cs.ChannelID(), clusterRelation, status)

	logger.Debugf("[channel: %s] Done creating channel support resources", cs.ChannelID())

	return cs, nil
}

func (cs *ChainSupport) Reader() blockledger.Reader {
	return cs
}

// Signer returns the SignerSerializer for this channel.
func (cs *ChainSupport) Signer() identity.SignerSerializer {
	return cs
}

func (cs *ChainSupport) start() {
	cs.Start()
}

// BlockCutter returns the blockcutter.Receiver instance for this channel.
func (cs *ChainSupport) BlockCutter() blockcutter.Receiver {
	return cs.cutter
}

// Validate passes through to the underlying configtx.Validator
func (cs *ChainSupport) Validate(configEnv *cb.ConfigEnvelope) error {
	return cs.ConfigtxValidator().Validate(configEnv)
}

// ProposeConfigUpdate validates a config update using the underlying configtx.Validator
// and the consensus.MetadataValidator.
func (cs *ChainSupport) ProposeConfigUpdate(configtx *cb.Envelope) (*cb.ConfigEnvelope, error) {
	env, err := cs.ConfigtxValidator().ProposeConfigUpdate(configtx)
	if err != nil {
		return nil, err
	}

	bundle, err := cs.CreateBundle(cs.ChannelID(), env.GetConfig())
	if err != nil {
		return nil, err
	}

	if err = checkResources(bundle); err != nil {
		return nil, errors.WithMessage(err, "config update is not compatible")
	}

	if err = cs.ValidateNew(bundle); err != nil {
		return nil, err
	}

	oldOrdererConfig, ok := cs.OrdererConfig()
	if !ok {
		logger.Panic("old config is missing orderer group")
	}

	// this is being validated in checkResources(bundle) earlier, so here we just panic
	newOrdererConfig, ok := bundle.OrdererConfig()
	if !ok {
		logger.Panic("new config is missing orderer group")
	}

	if err = cs.ValidateConsensusMetadata(oldOrdererConfig, newOrdererConfig, false); err != nil {
		return nil, errors.WithMessage(err, "consensus metadata update for channel config update is invalid")
	}

	return env, nil
}

// ConfigProto passes through to the underlying configtx.Validator
func (cs *ChainSupport) ConfigProto() *cb.Config {
	return cs.ConfigtxValidator().ConfigProto()
}

// Sequence passes through to the underlying configtx.Validator
func (cs *ChainSupport) Sequence() uint64 {
	return cs.ConfigtxValidator().Sequence()
}
