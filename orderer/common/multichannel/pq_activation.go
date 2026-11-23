// SPDX-License-Identifier: Apache-2.0

package multichannel

import (
	"crypto/mldsa"
	"fmt"
	"os"
	"path/filepath"

	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric/common/channelconfig"
	"github.com/hyperledger/fabric/common/ledger/blkstorage"
	"github.com/hyperledger/fabric/common/ledger/blockledger"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation"
	"github.com/hyperledger/fabric/orderer/common/localconfig"
	"github.com/hyperledger/fabric/orderer/common/types"
	"github.com/hyperledger/fabric/orderer/consensus/etcdraft"
	"github.com/hyperledger/fabric/protoutil"
)

type protectedChannels struct {
	config   localconfig.PQActivation
	channels map[string]*activation.Channel
	store    *activation.Store
	key      *mldsa.PublicKey
	err      error
}

func newProtectedChannels(config localconfig.PQActivation) protectedChannels {
	p := protectedChannels{config: config, channels: make(map[string]*activation.Channel)}
	for _, id := range config.Channels {
		p.channels[id] = nil
	}
	if len(p.channels) == 0 {
		return p
	}
	if config.StateDir == "" || config.TrustAnchor == "" || config.Network == "" || config.Node == "" {
		p.err = fmt.Errorf("protected orderer activation requires state directory, trust anchor, network and node")
		return p
	}
	key, err := os.ReadFile(config.TrustAnchor)
	if err == nil {
		p.key, err = mldsa.NewPublicKey(mldsa.MLDSA65(), key)
	}
	if err != nil {
		p.err = fmt.Errorf("read orderer policy trust anchor: %w", err)
		return p
	}
	p.store, p.err = activation.OpenStore(config.StateDir, nil)
	return p
}

func (p *protectedChannels) contains(id string) bool {
	_, ok := p.channels[id]
	return ok
}

func (r *Registrar) recordProtectedFailure(id string, err error) bool {
	if !r.protected.contains(id) {
		return false
	}
	if controller := r.protected.channels[id]; controller != nil {
		controller.Suspend()
	}
	info := types.ChannelInfo{Name: id, ConsensusRelation: types.ConsensusRelationConsenter, Status: types.StatusFailed}
	r.failedProtected[id] = info
	r.ReportConsensusRelationAndStatusMetrics(id, info.ConsensusRelation, info.Status)
	logger.Errorf("Protected channel %s stopped during initialization: %s", id, err)
	return true
}

func (r *Registrar) startupConfigBlock(id string, ledger blockledger.Reader) (*cb.Block, error) {
	if !r.protected.contains(id) {
		return ConfigBlockOrPanic(ledger), nil
	}
	if ledger.Height() == 0 {
		return nil, fmt.Errorf("protected ledger is empty")
	}
	tip, err := blockledger.GetBlockByNumber(ledger, ledger.Height()-1)
	if err != nil {
		return nil, err
	}
	index, err := protoutil.GetLastConfigIndexFromBlock(tip)
	if err != nil {
		return nil, err
	}
	block, err := blockledger.GetBlockByNumber(ledger, index)
	if err != nil {
		return nil, err
	}
	envelope, err := protoutil.ExtractEnvelope(block, 0)
	if err != nil {
		return nil, err
	}
	channelID, err := channelNameFromConfigTx(envelope)
	if err != nil || channelID != id {
		return nil, fmt.Errorf("protected config block conflicts with ledger channel %s", id)
	}
	return block, nil
}

// activationFor is called by the registrar while it owns channel lifecycle.
func (r *Registrar) activationFor(resources *ledgerResources) *activation.Channel {
	id := resources.ChannelID()
	existing, protected := r.protected.channels[id]
	if !protected || existing != nil {
		return existing
	}
	ledger := resources.ReadWriter
	var published *channelconfig.Bundle
	controller := &activation.Channel{
		BootstrapError: r.protected.err,
		Store:          r.protected.store, Gate: &activation.Gate{},
		Network: r.protected.config.Network, Node: r.protected.config.Node,
		ID: id, Signer: r.protected.key, Crypto: r.bccsp,
		Validate: func(candidate channelconfig.Resources) error {
			if err := checkResources(candidate); err != nil {
				return err
			}
			conf, _ := candidate.OrdererConfig()
			if err := etcdraft.ValidateConfigForActivation(conf); err != nil {
				return err
			}
			if candidate.ChannelConfig().Capabilities().PactwayHybridCertificateV1() {
				return validateHybridOrdererSigner(candidate, r.signer)
			}
			return nil
		},
		Ledger: activation.Ledger{
			Block: func(number uint64) (*cb.Block, error) {
				return blockledger.GetBlockByNumber(ledger, number)
			},
			Height: func() (uint64, error) { return ledger.Height(), nil },
			LatestConfig: func() (*cb.Block, error) {
				if ledger.Height() == 0 {
					return nil, fmt.Errorf("protected ledger is empty")
				}
				tip, err := blockledger.GetBlockByNumber(ledger, ledger.Height()-1)
				if err != nil {
					return nil, err
				}
				index, err := protoutil.GetLastConfigIndexFromBlock(tip)
				if err != nil {
					return nil, err
				}
				return blockledger.GetBlockByNumber(ledger, index)
			},
			Sync: func() error {
				return activation.SyncDirectory(filepath.Join(r.config.FileLedger.Location, blkstorage.ChainsDir, id))
			},
		},
		Publish: func(bundle *channelconfig.Bundle) error {
			if published != nil && published.ConfigtxValidator().Sequence() == bundle.ConfigtxValidator().Sequence() {
				return nil
			}
			for _, callback := range r.callbacks {
				callback(bundle)
			}
			published = bundle
			return nil
		},
	}
	r.protected.channels[id] = controller
	return controller
}
