/*
SPDX-License-Identifier: Apache-2.0
*/

package peer

import (
	"errors"
	"fmt"

	fabricerrors "github.com/hyperledger/fabric/common/errors"
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
		return c.requireRecovery(errors.New("protected peer commit requires a controller, ledger and block"))
	}
	if err := c.controller.ValidateBlockShape(data.Block); err != nil {
		return c.requireRecovery(err)
	}
	if protoutil.IsConfigBlock(data.Block) {
		err := c.controller.ApplyPeerConfig(data.Block, func() error {
			return c.Committer.CommitLegacy(data, opts)
		})
		if err != nil {
			return c.requireRecovery(err)
		}
		return nil
	}
	_, generation, release, ok := c.controller.Gate.Acquire()
	if !ok {
		return c.requireRecovery(errors.New("protected channel admission is closed"))
	}
	defer release()
	if err := generation.Err(); err != nil {
		release()
		return c.requireRecovery(err)
	}
	if err := c.Committer.CommitLegacy(data, opts); err != nil {
		release()
		return c.requireRecovery(err)
	}
	return nil
}

func (c *protectedCommitter) requireRecovery(cause error) error {
	if c.controller != nil && c.controller.Gate != nil {
		c.controller.Suspend()
	}
	return fmt.Errorf("%w: %w", fabricerrors.ErrProtectedChannelRecovery, cause)
}
