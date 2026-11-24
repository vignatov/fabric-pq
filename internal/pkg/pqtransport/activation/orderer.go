// SPDX-License-Identifier: Apache-2.0

package activation

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric/common/policies"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport"
	"github.com/hyperledger/fabric/protoutil"
)

// ErrNativeRecovery indicates that an authorized transition might already be
// durable and must be reconciled on restart before any further application.
var ErrNativeRecovery = errors.New("native orderer commit requires recovery")

// VerifyOrdererHistory verifies a bounded, contiguous catch-up range without
// changing the checkpoint, ledger, or active bundle. All config transitions
// are checked against the preceding verified block and policy.
func (c *Channel) VerifyOrdererHistory(tip *cb.Block, blocks []*cb.Block) error {
	s := c.Store
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := c.checkQuarantine(); err != nil {
		return err
	}
	previous, err := c.latest()
	if err != nil {
		return err
	}
	current, err := readRecord[checkpoint](s.dir, "checkpoint")
	if err != nil {
		return err
	}
	pending, err := s.readJournal()
	if err != nil {
		return err
	}
	for _, block := range blocks {
		if err := c.ValidateBlockShape(block); err != nil {
			return err
		}
		if block.GetHeader() == nil || tip.GetHeader() == nil ||
			block.GetHeader().GetNumber() != tip.GetHeader().GetNumber()+1 ||
			!bytes.Equal(block.GetHeader().GetPreviousHash(), protoutil.BlockHeaderHash(tip.GetHeader())) ||
			!bytes.Equal(block.GetHeader().GetDataHash(), protoutil.ComputeBlockDataHash(block.GetData())) {
			return errors.New("invalid block chain in catch-up history")
		}
		policy, ok := previous.bundle.PolicyManager().GetPolicy(policies.BlockValidation)
		if !ok {
			return errors.New("missing previous block validation policy")
		}
		if err := protoutil.BlockSignatureVerifier(false, nil, policy)(block.GetHeader(), block.GetMetadata()); err != nil {
			return fmt.Errorf("verify catch-up block signature: %w", err)
		}
		tip = block
		if !protoutil.IsConfigBlock(block) {
			continue
		}
		next, err := c.config(block)
		if err != nil {
			return err
		}
		if err := c.verifyFabric(previous, next); err != nil {
			return err
		}
		var record journal
		if pending.Phase == prepared || pending.Phase == commitPending {
			if pending.Channel != c.ID || pending.Base != previous.identity ||
				pending.Block != next.identity || pending.Previous.Checkpoint != current.Checkpoint {
				return errors.New("catch-up block conflicts with prepared transition")
			}
			record = pending
			pending = journal{}
		} else {
			auth, err := c.stagedAuthorization(current.Version + 1)
			if err != nil {
				return fmt.Errorf("load catch-up operator approval: %w", err)
			}
			record = c.record(previous, next, current, auth)
		}
		if err := c.verifyOperator(previous, next, record); err != nil {
			return err
		}
		previous, current = next, record.Next
	}
	return nil
}

// ValidateBlockShape prevents malformed or mixed blocks from bypassing CONFIG
// detection in a protected native application path.
func (c *Channel) ValidateBlockShape(block *cb.Block) error {
	data := block.GetData().GetData()
	if block.GetHeader() == nil || len(data) == 0 ||
		!bytes.Equal(block.GetHeader().GetDataHash(), protoutil.ComputeBlockDataHash(block.GetData())) {
		return errors.New("invalid protected Fabric block header or data")
	}
	for _, raw := range data {
		envelope, err := protoutil.GetEnvelopeFromBlock(raw)
		if err != nil {
			return err
		}
		header, err := protoutil.ChannelHeader(envelope)
		if err != nil || header.GetChannelId() != c.ID {
			return errors.New("invalid protected block envelope or channel identity")
		}
		switch cb.HeaderType(header.GetType()) {
		case cb.HeaderType_CONFIG:
			if len(data) != 1 {
				return errors.New("configuration mixed with other transactions")
			}
		case cb.HeaderType_CONFIG_UPDATE, cb.HeaderType_ORDERER_TRANSACTION:
			return errors.New("invalid ordered configuration envelope type")
		}
	}
	return nil
}

// RecoverOrdererLedger authenticates the ledger and repairs an interrupted
// checkpoint write without opening admission or discarding a prepared block.
func (c *Channel) RecoverOrdererLedger() error {
	return c.recover(false, true, false)
}

// CompleteOrdererReplay is called by the Raft application owner after it has
// reconciled the persisted log and a quorum read barrier.
func (c *Channel) CompleteOrdererReplay() error {
	return c.recover(true, true, false)
}

func (c *Channel) Ready() bool {
	return c.Gate.isOpen()
}

func (c *Channel) Suspend() {
	c.Gate.close()
}

// QuarantineOrderer persists a terminal failure found outside the ledger
// transaction, such as a conflicting Raft snapshot.
func (c *Channel) QuarantineOrderer(cause error) error {
	if c.BootstrapError != nil {
		return errors.Join(c.BootstrapError, cause)
	}
	c.Store.mu.Lock()
	defer c.Store.mu.Unlock()
	if err := c.checkQuarantine(); err != nil {
		c.Gate.close()
		return err
	}
	return c.quarantine(cause)
}

func (c *Channel) stagedAuthorization(version uint64) (Authorization, error) {
	name := fmt.Sprintf("approval-%s-%d", digest([]byte(c.ID)), version)
	return readRecord[Authorization](c.Store.dir, name)
}

func (c *Channel) record(previous, next configuration, current checkpoint, auth Authorization) journal {
	return journal{
		Phase: prepared, Channel: c.ID, Base: previous.identity, Block: next.identity, Previous: current,
		Next: checkpoint{
			Checkpoint: pqtransport.Checkpoint{Version: current.Version + 1, Digest: sha256.Sum256(auth.Policy)},
			Policy:     signedDocument{auth.Policy, auth.PolicySignature},
		},
		Operation: signedDocument{auth.Transition, auth.TransitionSignature},
	}
}

// PrepareOrdererProposal binds approved configuration content to the leader's
// proposed header. The apply path still checks the actual predecessor block.
func (c *Channel) PrepareOrdererProposal(block *cb.Block) error {
	s := c.Store
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := c.checkQuarantine(); err != nil {
		return err
	}
	if !c.Ready() {
		return errors.New("protected channel is recovering")
	}
	previous, err := c.latest()
	if err != nil {
		return err
	}
	next, err := c.config(block)
	if err != nil {
		return err
	}
	if err := c.verifyFabric(previous, next); err != nil {
		return err
	}
	current, err := readRecord[checkpoint](s.dir, "checkpoint")
	if err != nil {
		return c.quarantineNode(err)
	}
	pending, err := s.readJournal()
	if err != nil {
		return c.quarantineNode(err)
	}
	if pending.Phase == prepared || pending.Phase == commitPending {
		return errors.New("an activation transition already requires recovery")
	}
	auth, err := c.stagedAuthorization(current.Version + 1)
	if err != nil {
		return fmt.Errorf("load operator approval: %w", err)
	}
	record := c.record(previous, next, current, auth)
	if err := c.verifyOperator(previous, next, record); err != nil {
		return err
	}
	return s.write("journal", record)
}

// ApplyOrdererConfig guards an ordered block even while admission is closed
// for replay. The caller serializes it with other native applications.
func (c *Channel) ApplyOrdererConfig(block *cb.Block, commit func() error) error {
	err := c.apply(block, Authorization{}, commit, true, false)
	if errors.Is(err, ErrNativeRecovery) {
		return err
	}
	if err != nil {
		return c.QuarantineOrderer(err)
	}
	return nil
}

// VerifyGenesis checks the independently provisioned exact block identity.
func (c *Channel) VerifyGenesis(block *cb.Block) error {
	if c.BootstrapError != nil {
		return c.BootstrapError
	}
	s := c.Store
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := c.checkQuarantine(); err != nil {
		return err
	}
	genesis, err := c.config(block)
	if err != nil {
		return err
	}
	expected, err := readRecord[string](s.dir, "genesis-"+digest([]byte(c.ID)))
	if err != nil {
		return fmt.Errorf("read protected genesis anchor: %w", err)
	}
	if genesis.identity.Number != 0 || genesis.binding.Sequence != 0 ||
		len(block.GetHeader().GetPreviousHash()) != 0 || genesis.identity.Header != expected {
		return errors.New("block conflicts with protected genesis anchor")
	}
	if c.Validate != nil {
		return c.Validate(genesis.bundle)
	}
	return nil
}

// AuthorizeGenesis is required before the initial append on an empty ledger.
func (c *Channel) AuthorizeGenesis(block *cb.Block) error {
	if err := c.VerifyGenesis(block); err != nil {
		return err
	}
	c.Store.mu.Lock()
	defer c.Store.mu.Unlock()
	saved, err := readRecord[checkpoint](c.Store.dir, "checkpoint")
	if err != nil {
		return c.quarantineNode(err)
	}
	policy, err := c.authenticate(saved)
	if err != nil {
		return c.quarantineNode(err)
	}
	cfg, err := c.config(block)
	if err != nil {
		return err
	}
	return c.match(policy, cfg)
}

func (c *Channel) GenesisBlock() (*cb.Block, error) {
	if c.BootstrapError != nil {
		return nil, c.BootstrapError
	}
	raw, err := os.ReadFile(filepath.Join(c.Store.dir, "genesis-"+digest([]byte(c.ID))+".block"))
	if err != nil {
		return nil, err
	}
	block, err := protoutil.UnmarshalBlock(raw)
	if err != nil {
		return nil, err
	}
	return block, c.VerifyGenesis(block)
}

// CheckRaftStorage detects disappearance of a previously opened WAL. The
// marker records local ownership only. Commit and apply indices stay in Fabric.
func (c *Channel) CheckRaftStorage(fresh bool) error {
	s := c.Store
	s.mu.Lock()
	defer s.mu.Unlock()
	name := "raft-" + digest([]byte(c.ID))
	marker, err := readRecord[string](s.dir, name)
	if err == nil {
		if marker != c.ID || fresh {
			return c.quarantine(errors.New("previously established channel Raft WAL is missing or inconsistent"))
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return c.quarantine(err)
	}
	return nil
}

func (c *Channel) MarkRaftStorage() error {
	c.Store.mu.Lock()
	defer c.Store.mu.Unlock()
	return c.Store.write("raft-"+digest([]byte(c.ID)), c.ID)
}
