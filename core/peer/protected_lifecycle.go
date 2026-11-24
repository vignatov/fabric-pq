/*
SPDX-License-Identifier: Apache-2.0
*/

package peer

import (
	"errors"

	"github.com/hyperledger/fabric/common/channelconfig"
	"github.com/hyperledger/fabric/core/committer"
	"github.com/hyperledger/fabric/core/ledger"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation"
)

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
	err := controller.InstallPublisher(func(bundle *channelconfig.Bundle) error {
		if err := p.publishProtectedResources(bundle); err != nil {
			return err
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
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &protectedLifecycle{
		serving: serving, validation: validation,
		committer: &protectedCommitter{Committer: native, controller: controller},
	}, nil
}
