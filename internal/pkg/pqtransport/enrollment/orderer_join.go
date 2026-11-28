/*
SPDX-License-Identifier: Apache-2.0
*/

package enrollment

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"

	"github.com/hyperledger/fabric-lib-go/bccsp"
	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation"
	"github.com/hyperledger/fabric/protoutil"
	"google.golang.org/protobuf/proto"
)

// OrdererJoinAnchorDomain separates approval to onboard from other operator
// signatures, including approval to activate a configuration.
const OrdererJoinAnchorDomain = "fabric-pq/orderer-join/v1\x00"

// JoinAnchor binds a managed node to one channel and configuration block.
type JoinAnchor struct {
	Network     string                     `json:"network"`
	Node        string                     `json:"node"`
	Profile     string                     `json:"profile"`
	Channel     string                     `json:"channel"`
	GenesisHash string                     `json:"genesis_hash"`
	BlockNumber uint64                     `json:"block_number"`
	BlockHash   string                     `json:"block_hash"`
	Config      pqtransport.ChannelBinding `json:"config"`
}

// VerifyOrdererJoin authenticates a non-genesis join before the registrar
// creates a ledger or uses the target to derive consortium membership.
// It is also required when the registrar loads a pending join after restart.
func (r *Registry) VerifyOrdererJoin(id string, block *cb.Block, crypto bccsp.BCCSP) error {
	controller := r.Controller(id, crypto)
	if controller == nil || block.GetHeader().GetNumber() == 0 {
		return errors.New("signed orderer join anchor requires a protected channel and a non-genesis block")
	}
	var anchor JoinAnchor
	if err := r.readJoinAnchor("join-orderer", id, OrdererJoinAnchorDomain, &anchor); err != nil {
		return err
	}
	genesis, err := controller.GenesisBlock()
	if err != nil {
		return fmt.Errorf("verify genesis for orderer join: %w", err)
	}
	expected, err := r.joinAnchor(controller, genesis, block)
	if err != nil {
		return err
	}
	if anchor != expected {
		return errors.New("signed orderer join anchor conflicts with genesis, join block, or protected node policy")
	}
	return nil
}

func (r *Registry) joinAnchor(controller *activation.Channel, genesis, block *cb.Block) (JoinAnchor, error) {
	if err := controller.VerifyCapabilityBinding(genesis, block); err != nil {
		return JoinAnchor{}, err
	}
	if err := controller.ValidateBlockShape(block); err != nil {
		return JoinAnchor{}, err
	}
	if number := block.GetHeader().GetNumber(); number == 0 || number == math.MaxUint64 {
		return JoinAnchor{}, errors.New("invalid non-genesis join height")
	}
	env, err := protoutil.ExtractEnvelope(block, 0)
	if err != nil {
		return JoinAnchor{}, err
	}
	config := &cb.ConfigEnvelope{}
	if _, err := protoutil.UnmarshalEnvelopeOfType(env, cb.HeaderType_CONFIG, config); err != nil {
		return JoinAnchor{}, err
	}
	if config.GetConfig().GetSequence() == 0 {
		return JoinAnchor{}, errors.New("non-genesis join requires a configuration transition")
	}
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(config.GetConfig())
	if err != nil {
		return JoinAnchor{}, err
	}
	return JoinAnchor{
		Network: r.network, Node: r.node, Profile: pqtransport.ProfileV1, Channel: controller.ID,
		GenesisHash: hex.EncodeToString(protoutil.BlockHeaderHash(genesis.GetHeader())),
		BlockNumber: block.GetHeader().GetNumber(),
		BlockHash:   hex.EncodeToString(protoutil.BlockHeaderHash(block.GetHeader())),
		Config: pqtransport.ChannelBinding{
			Sequence: config.GetConfig().GetSequence(),
			Digest:   fmt.Sprintf("%x", sha256.Sum256(encoded)),
		},
	}, nil
}

func (r *Registry) readJoinAnchor(prefix, id, domain string, anchor any) error {
	name := joinEvidenceName(prefix, id)
	raw, err := os.ReadFile(filepath.Join(r.stateDir, name))
	if err != nil {
		return fmt.Errorf("read %s anchor: %w", prefix, err)
	}
	if _, err := verify(raw, r.key, domain, anchor); err != nil {
		return fmt.Errorf("verify %s anchor: %w", prefix, err)
	}
	return nil
}

func joinEvidenceName(prefix, id string) string {
	return fmt.Sprintf("%s-%x", prefix, sha256.Sum256([]byte(id)))
}
