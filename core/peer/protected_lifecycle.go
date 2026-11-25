/*
SPDX-License-Identifier: Apache-2.0
*/

package peer

import (
	"errors"
	"path/filepath"

	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric/common/channelconfig"
	"github.com/hyperledger/fabric/common/ledger/blkstorage"
	"github.com/hyperledger/fabric/core/committer"
	"github.com/hyperledger/fabric/core/ledger"
	"github.com/hyperledger/fabric/core/ledger/kvledger"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation"
	"github.com/hyperledger/fabric/protoutil"
	"google.golang.org/protobuf/proto"
)

func validateProtectedPeerConfig(res channelconfig.Resources) error {
	app, ok := res.ApplicationConfig()
	if !ok {
		return errors.New("protected peer channel requires application configuration")
	}
	if _, ok := res.OrdererConfig(); !ok {
		return errors.New("protected peer channel requires orderer configuration")
	}
	if err := app.Capabilities().Supported(); err != nil {
		return err
	}
	if err := res.ChannelConfig().Capabilities().Supported(); err != nil {
		return err
	}
	return validateHybridLocalSigner(res)
}

func (p *Peer) protectedController(id string, l ledger.PeerLedger) *activation.Channel {
	if p.ProtectedRegistry == nil {
		return nil
	}
	controller := p.ProtectedRegistry.Controller(id, p.CryptoProvider)
	if controller == nil {
		return nil
	}
	controller.Validate = validateProtectedPeerConfig
	controller.Ledger = activation.Ledger{
		Block: l.GetBlockByNumber,
		Height: func() (uint64, error) {
			info, err := l.GetBlockchainInfo()
			return info.GetHeight(), err
		},
		LatestConfig: func() (*cb.Block, error) {
			block, err := ConfigBlockFromLedger(l)
			if err != nil {
				return nil, err
			}
			env, err := protoutil.ExtractEnvelope(block, 0)
			if err != nil {
				return nil, err
			}
			config := &cb.ConfigEnvelope{}
			if _, err := protoutil.UnmarshalEnvelopeOfType(env, cb.HeaderType_CONFIG, config); err != nil {
				return nil, err
			}
			worldState, err := RetrievePersistedChannelConfig(l)
			if err != nil {
				return nil, err
			}
			if !proto.Equal(worldState, config.GetConfig()) {
				return nil, errors.New("world state conflicts with committed config block")
			}
			return block, nil
		},
		Sync: func() error {
			root := kvledger.BlockStorePath(p.ProtectedRegistry.LedgerRoot())
			return activation.SyncDirectory(filepath.Join(root, blkstorage.ChainsDir, id))
		},
	}
	return controller
}

// protectedLifecycle keeps candidate validation resources separate from the
// serving channel. Its owner must construct it before exposing the channel,
// configure every required resource publisher, and recover the controller.
type protectedLifecycle struct {
	serving    *Channel
	validation *Channel
	committer  committer.Committer
}

// recover installs the committed resources before opening the serving gate.
func (l *protectedLifecycle) recover() error {
	return l.serving.activation.RecoverPeer()
}

func (p *Peer) newProtectedLifecycle(controller *activation.Channel, l ledger.PeerLedger, initial *channelconfig.Bundle, native committer.Committer, actors ...channelconfig.BundleActor) (*protectedLifecycle, error) {
	if controller == nil || controller.Store == nil || controller.Gate == nil || l == nil || initial == nil || native == nil {
		return nil, errors.New("protected peer lifecycle requires controller, ledger, bundle and committer")
	}
	if initial.ConfigtxValidator().ChannelID() != controller.ID {
		return nil, errors.New("protected peer bundle conflicts with controller channel")
	}
	serving := &Channel{ledger: l, cryptoProvider: p.CryptoProvider, activation: controller}
	validation := &Channel{ledger: l, cryptoProvider: p.CryptoProvider, resources: initial}
	validation.bundleSource = channelconfig.NewBundleSource(initial, validation.bundleUpdate)
	callbacks := append([]channelconfig.BundleActor{serving.bundleUpdate}, actors...)
	err := controller.InstallPublisherWithBarrier(func(bundle *channelconfig.Bundle) (func(), error) {
		release, err := p.beginProtectedPublication(bundle)
		if err != nil {
			return nil, err
		}
		// Validation may have applied a candidate that did not commit. Reset
		// it to the authenticated ledger bundle before serving can reopen.
		validation.applyLock.Lock()
		validation.bundleSource.Update(bundle)
		validation.applyLock.Unlock()
		if serving.bundleSource == nil {
			serving.bundleSource = channelconfig.NewBundleSource(bundle, callbacks...)
		} else {
			serving.bundleSource.Update(bundle)
		}
		return release, nil
	})
	if err != nil {
		return nil, err
	}
	return &protectedLifecycle{
		serving: serving, validation: validation,
		committer: &protectedCommitter{Committer: native, controller: controller},
	}, nil
}
