/*
SPDX-License-Identifier: Apache-2.0
*/

package activation

import (
	"bytes"
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"github.com/hyperledger/fabric-lib-go/bccsp"
	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric/common/channelconfig"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport"
	"github.com/hyperledger/fabric/protoutil"
	"google.golang.org/protobuf/proto"
)

type blockIdentity struct {
	Number uint64
	Header string
}

// Ledger is the local, Fabric-recovered view. LatestConfig must use the
// durable block store and, on a peer, cross-check recovered world state.
type Ledger struct {
	LatestConfig func() (*cb.Block, error)
	Block        func(uint64) (*cb.Block, error)
	Height       func() (uint64, error)
	Sync         func() error
}

// Authorization carries the independently signed operator transition and
// replacement node policy.
type Authorization struct {
	Transition          []byte
	TransitionSignature []byte
	Policy              []byte
	PolicySignature     []byte
}

// Channel connects the proof to one channel's native ledger and publication
// boundary. An orderer must complete native replay before recovering readiness.
type Channel struct {
	Store    *Store
	Gate     *Gate
	Ledger   Ledger
	Network  string
	Node     string
	ID       string
	Signer   *mldsa.PublicKey
	Crypto   bccsp.BCCSP
	Validate func(previous, candidate *channelconfig.Bundle) error
	Publish  func(*channelconfig.Bundle) error
}

type configuration struct {
	identity blockIdentity
	envelope *cb.ConfigEnvelope
	bundle   *channelconfig.Bundle
	binding  pqtransport.ChannelBinding
}

func (c *Channel) config(block *cb.Block) (configuration, error) {
	var result configuration
	if block.GetHeader() == nil || len(block.GetData().GetData()) != 1 ||
		!bytes.Equal(protoutil.ComputeBlockDataHash(block.GetData()), block.GetHeader().GetDataHash()) {
		return result, errors.New("invalid configuration block data or header")
	}
	envelope, err := protoutil.ExtractEnvelope(block, 0)
	if err != nil {
		return result, err
	}
	config := &cb.ConfigEnvelope{}
	header, err := protoutil.UnmarshalEnvelopeOfType(envelope, cb.HeaderType_CONFIG, config)
	if err != nil {
		return result, err
	}
	if header.GetChannelId() != c.ID || config.GetConfig() == nil {
		return result, errors.New("configuration block conflicts with channel identity")
	}
	bundle, err := channelconfig.NewBundle(c.ID, config.GetConfig(), c.Crypto)
	if err != nil {
		return result, err
	}
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(config.GetConfig())
	if err != nil {
		return result, err
	}
	return configuration{
		identity: blockIdentity{Number: block.GetHeader().GetNumber(), Header: hex.EncodeToString(protoutil.BlockHeaderHash(block.GetHeader()))},
		envelope: config,
		bundle:   bundle,
		binding:  pqtransport.ChannelBinding{Sequence: config.GetConfig().GetSequence(), Digest: digest(encoded)},
	}, nil
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func (c *Channel) authenticate(saved checkpoint) (*pqtransport.Policy, error) {
	return pqtransport.Authenticate(saved.Policy.Payload, saved.Policy.Signature, c.Signer, &saved.Checkpoint, c.Network, c.Node)
}

func (c *Channel) verifyFabric(previous, next configuration) error {
	if err := previous.bundle.ConfigtxValidator().Validate(next.envelope); err != nil {
		return fmt.Errorf("Fabric config authorization: %w", err)
	}
	if err := previous.bundle.ValidateNew(next.bundle); err != nil {
		return err
	}
	if c.Validate != nil {
		return c.Validate(previous.bundle, next.bundle)
	}
	return nil
}

func (c *Channel) verifyOperator(previous, next configuration, record journal) error {
	policy, err := c.authenticate(record.Previous)
	if err != nil {
		return err
	}
	if err := c.match(policy, previous); err != nil {
		return err
	}
	approved, err := pqtransport.VerifyOperatorTransition(policy, record.Operation.Payload, record.Operation.Signature,
		record.Next.Policy.Payload, record.Next.Policy.Signature, c.Signer, next.envelope.GetConfig())
	if err != nil {
		return fmt.Errorf("operator authorization: %w", err)
	}
	verified, err := approved.Checkpoint()
	if err != nil {
		return err
	}
	if verified != record.Next.Checkpoint {
		return errors.New("verified policy conflicts with proposed checkpoint")
	}
	return c.match(approved, next)
}

func (c *Channel) match(policy *pqtransport.Policy, current configuration) error {
	binding, found := policy.Channel(c.ID)
	if !found || binding != current.binding {
		return errors.New("committed configuration conflicts with protected checkpoint")
	}
	return nil
}

func (c *Channel) latest() (configuration, error) {
	block, err := c.Ledger.LatestConfig()
	if err != nil {
		return configuration{}, err
	}
	return c.config(block)
}

func (c *Channel) quarantineName() string {
	return "quarantine-" + digest([]byte(c.ID))
}

func (c *Channel) quarantine(cause error) error {
	c.Gate.close()
	err := c.Store.write(c.quarantineName(), cause.Error())
	return errors.Join(fmt.Errorf("channel %s quarantined: %w", c.ID, cause), err)
}

const nodeQuarantine = "quarantine-node"

func (c *Channel) quarantineNode(cause error) error {
	c.Store.closeGates()
	err := c.Store.write(nodeQuarantine, cause.Error())
	return errors.Join(fmt.Errorf("node quarantined: %w", cause), err)
}

func (c *Channel) checkQuarantine() error {
	for _, name := range []string{nodeQuarantine, c.quarantineName()} {
		reason, err := readRecord[string](c.Store.dir, name)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		return fmt.Errorf("channel %s quarantined: %s", c.ID, reason)
	}
	return nil
}

func (s *Store) readJournal() (journal, error) {
	record, err := readRecord[journal](s.dir, "journal")
	if errors.Is(err, os.ErrNotExist) {
		return journal{}, nil
	}
	if err != nil {
		return journal{}, err
	}
	switch record.Phase {
	case prepared, commitPending, active, aborted:
		if record.Channel != "" && record.Block.Header != "" && record.Base.Header != "" {
			return record, nil
		}
	}
	return journal{}, errors.New("invalid activation journal")
}

// Apply processes a concrete ordered configuration block. Native commit may
// leave an ambiguous durable outcome on error, so the gate stays closed until
// recovery. A Fabric-invalid candidate cannot enter the native commit path.
func (c *Channel) Apply(block *cb.Block, auth Authorization, commit func() error) error {
	s := c.Store
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := c.checkQuarantine(); err != nil {
		c.Gate.close()
		return err
	}
	if s.gates[c.ID] != c.Gate || !c.Gate.isOpen() {
		return errors.New("channel must establish native readiness before applying a configuration")
	}
	previous, err := c.latest()
	if err != nil {
		return c.quarantine(err)
	}
	next, err := c.config(block)
	if err != nil {
		return err
	}
	// Reject an invalid or replayed Fabric update before looking for local
	// authorization. An ordered, Fabric-valid update with missing local
	// authorization instead requires persistent quarantine.
	if err := c.verifyFabric(previous, next); err != nil {
		return err
	}
	current, err := readRecord[checkpoint](s.dir, "checkpoint")
	if err != nil {
		return c.quarantineNode(err)
	}
	if _, err := c.authenticate(current); err != nil {
		return c.quarantineNode(err)
	}
	pending, err := s.readJournal()
	if err != nil {
		return c.quarantineNode(err)
	}
	if pending.Phase == prepared || pending.Phase == commitPending {
		if pending.Channel == c.ID {
			c.Gate.close()
		}
		return errors.New("an activation transition already requires recovery")
	}
	height, err := c.Ledger.Height()
	if err != nil || height == 0 {
		return c.quarantine(errors.Join(errors.New("cannot establish the ledger tip"), err))
	}
	tip, err := c.Ledger.Block(height - 1)
	if err != nil || tip.GetHeader() == nil {
		return c.quarantine(errors.Join(errors.New("cannot read the ledger tip"), err))
	}
	if current.Version+1 == 0 || next.identity.Number != height ||
		!bytes.Equal(block.GetHeader().GetPreviousHash(), protoutil.BlockHeaderHash(tip.GetHeader())) {
		return c.quarantine(errors.New("invalid checkpoint version or configuration block order"))
	}
	record := journal{
		Phase: prepared, Channel: c.ID, Base: previous.identity, Block: next.identity, Previous: current,
		Next: checkpoint{
			Checkpoint: pqtransport.Checkpoint{Version: current.Version + 1, Digest: sha256.Sum256(auth.Policy)},
			Policy:     signedDocument{auth.Policy, auth.PolicySignature},
		},
		Operation: signedDocument{auth.Transition, auth.TransitionSignature},
	}
	if err := c.verifyOperator(previous, next, record); err != nil {
		return c.quarantine(err)
	}
	s.probe("before-prepare")
	if err := s.write("journal", record); err != nil {
		c.Gate.close()
		return err
	}
	c.Gate.close()
	record.Phase = commitPending
	if err := s.write("journal", record); err != nil {
		return err
	}
	s.probe("before-ledger-commit")
	if err := commit(); err != nil {
		return fmt.Errorf("native commit outcome requires recovery: %w", err)
	}
	s.probe("after-ledger-commit")
	committed, err := c.latest()
	if err != nil || committed.identity != record.Block {
		return c.quarantine(errors.Join(errors.New("native commit does not match prepared block"), err))
	}
	return c.finish(record, committed, current)
}

func (c *Channel) finish(record journal, committed configuration, current checkpoint) error {
	s := c.Store
	if err := c.Ledger.Sync(); err != nil {
		return err
	}
	s.probe("ledger-durable")
	switch current.Checkpoint {
	case record.Previous.Checkpoint:
		if err := s.write("checkpoint", record.Next); err != nil {
			return err
		}
	case record.Next.Checkpoint:
	default:
		return c.quarantine(errors.New("checkpoint conflicts with prepared transition"))
	}
	s.probe("before-publication")
	if c.Publish != nil {
		if err := c.Publish(committed.bundle); err != nil {
			return fmt.Errorf("publish configuration: %w", err)
		}
	}
	s.probe("after-publication")
	record.Phase = active
	if err := s.write("journal", record); err != nil {
		return err
	}
	c.Gate.publish(committed.bundle)
	s.probe("active")
	return nil
}

// Recover reconciles the reopened ledger, checkpoint and write-ahead record
// before installing an active generation. replaySettled describes native
// orderer application readiness, including any pending committed Raft entry.
func (c *Channel) Recover(replaySettled bool) error {
	s := c.Store
	s.mu.Lock()
	defer s.mu.Unlock()
	if old := s.gates[c.ID]; old != nil && old != c.Gate {
		old.close()
	}
	s.gates[c.ID] = c.Gate
	c.Gate.close()
	if err := c.checkQuarantine(); err != nil {
		return err
	}
	if !replaySettled {
		return errors.New("native replay must settle before activation")
	}
	current, err := readRecord[checkpoint](s.dir, "checkpoint")
	if err != nil {
		return c.quarantineNode(err)
	}
	policy, err := c.authenticate(current)
	if err != nil {
		return c.quarantineNode(err)
	}
	committed, err := c.latest()
	if err != nil {
		return c.quarantine(err)
	}
	record, err := s.readJournal()
	if err != nil {
		return c.quarantineNode(err)
	}
	if record.Channel == c.ID && (record.Phase == prepared || record.Phase == commitPending || record.Phase == active) {
		switch {
		case committed.identity == record.Block && record.Phase != prepared:
			base, err := c.Ledger.Block(record.Base.Number)
			if err != nil {
				return c.quarantine(err)
			}
			previous, err := c.config(base)
			if err != nil || previous.identity != record.Base {
				return c.quarantine(errors.Join(errors.New("prepared base block conflicts with ledger"), err))
			}
			if err := c.verifyFabric(previous, committed); err != nil {
				return c.quarantine(err)
			}
			if err := c.verifyOperator(previous, committed, record); err != nil {
				return c.quarantine(err)
			}
			if record.Phase != active {
				return c.finish(record, committed, current)
			}
			if current.Checkpoint != record.Next.Checkpoint {
				return c.quarantine(errors.New("active journal conflicts with checkpoint"))
			}
		case committed.identity == record.Base && record.Phase != active && current.Checkpoint == record.Previous.Checkpoint:
			height, err := c.Ledger.Height()
			if err != nil || height > record.Block.Number {
				return c.quarantine(errors.Join(errors.New("prepared block position conflicts with ledger"), err))
			}
			record.Phase = aborted
			if err := s.write("journal", record); err != nil {
				return err
			}
		default:
			return c.quarantine(errors.New("committed configuration conflicts with activation journal"))
		}
	}
	if err := c.match(policy, committed); err != nil {
		return c.quarantine(err)
	}
	if c.Publish != nil {
		if err := c.Publish(committed.bundle); err != nil {
			return err
		}
	}
	c.Gate.publish(committed.bundle)
	return nil
}
