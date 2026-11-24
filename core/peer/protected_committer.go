/*
SPDX-License-Identifier: Apache-2.0
*/

package peer

import (
	"errors"

	"github.com/hyperledger/fabric/core/committer"
	"github.com/hyperledger/fabric/core/ledger"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation"
	"github.com/hyperledger/fabric/protoutil"
)

// protectedCommitter couples native commits to the authenticated channel
// controller. The enclosing peer must isolate validation resources and wire all
// admission and publication boundaries before enabling this path.
type protectedCommitter struct {
	committer.Committer
	controller *activation.Channel
}

func (c *protectedCommitter) CommitLegacy(data *ledger.BlockAndPvtData, opts *ledger.CommitOptions) error {
	if c.controller == nil || c.controller.Gate == nil || c.Committer == nil || data == nil || data.Block == nil {
		return errors.New("protected peer commit requires a controller, ledger and block")
	}
	if err := c.controller.ValidateBlockShape(data.Block); err != nil {
		return err
	}
	if protoutil.IsConfigBlock(data.Block) {
		return c.controller.ApplyPeerConfig(data.Block, func() error {
			return c.Committer.CommitLegacy(data, opts)
		})
	}
	_, generation, release, ok := c.controller.Gate.Acquire()
	if !ok {
		return errors.New("protected channel admission is closed")
	}
	defer release()
	if err := generation.Err(); err != nil {
		return err
	}
	return c.Committer.CommitLegacy(data, opts)
}
