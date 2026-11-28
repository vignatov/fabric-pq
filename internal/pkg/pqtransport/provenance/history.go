/*
SPDX-License-Identifier: Apache-2.0
*/

// Package provenance verifies a complete Fabric channel history from an
// independently trusted genesis block to a supported configuration boundary.
package provenance

import (
	"bytes"
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hyperledger/fabric-lib-go/bccsp"
	"github.com/hyperledger/fabric-lib-go/common/flogging"
	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric/common/channelconfig"
	"github.com/hyperledger/fabric/common/deliverclient"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport"
	"github.com/hyperledger/fabric/orderer/consensus/etcdraft"
	"github.com/hyperledger/fabric/protoutil"
	"google.golang.org/protobuf/proto"
)

const FormatVersion = "fabric-pq/fabric-history/v1"

type Request struct {
	Network            string
	Node               string
	Channel            string
	TrustedGenesisHash string
	TargetBlockNumber  uint64
	History            []*cb.Block
	Policy             *pqtransport.Policy
	Crypto             bccsp.BCCSP
}

type PolicyIdentity struct {
	ConfigBlockNumber   uint64 `json:"config_block_number"`
	ConfigSequence      uint64 `json:"config_sequence"`
	ConfigurationDigest string `json:"configuration_digest"`
	PolicyDigest        string `json:"policy_digest"`
}

type Report struct {
	FormatVersion                string           `json:"format_version"`
	Network                      string           `json:"network"`
	Node                         string           `json:"node"`
	Channel                      string           `json:"channel"`
	TrustedGenesisBlockIdentity  string           `json:"trusted_genesis_block_identity"`
	SourceHistoryIdentity        string           `json:"source_history_identity"`
	VerifiedFromBlock            uint64           `json:"verified_from_block"`
	VerifiedThroughBlock         uint64           `json:"verified_through_block"`
	TargetBlockNumber            uint64           `json:"target_block_number"`
	TargetBlockHash              string           `json:"target_block_hash"`
	TargetConfigurationSequence  uint64           `json:"target_configuration_sequence"`
	TargetConfigurationDigest    string           `json:"target_configuration_digest"`
	VerificationPolicyIdentities []PolicyIdentity `json:"verification_policy_identities"`
	RequiredTransportProfile     string           `json:"required_transport_profile"`
	TargetJoinAnchorDigest       string           `json:"target_join_anchor_digest"`
	VerificationResult           string           `json:"verification_result"`
	FailureReason                string           `json:"failure_reason,omitempty"`
}

type JoinIdentity struct {
	Network     string
	Node        string
	Profile     string
	Channel     string
	GenesisHash string
	BlockNumber uint64
	BlockHash   string
	Config      pqtransport.ChannelBinding
}

// VerifiedHistory is an unforgeable-in-package result of VerifyHistory.
// Callers receive copies of report data and blocks to prevent mutation of the
// verified evidence after validation.
type VerifiedHistory struct {
	report   Report
	target   *cb.Block
	identity JoinIdentity
	policy   *pqtransport.Policy
	verified bool
}

func (v *VerifiedHistory) Verified() bool {
	return v != nil && v.verified
}

func (v *VerifiedHistory) Report() Report {
	if !v.Verified() {
		return Report{}
	}
	report := v.report
	report.VerificationPolicyIdentities = append([]PolicyIdentity(nil), v.report.VerificationPolicyIdentities...)
	return report
}

func (v *VerifiedHistory) TargetBlock() *cb.Block {
	if !v.Verified() {
		return nil
	}
	return proto.Clone(v.target).(*cb.Block)
}

func (v *VerifiedHistory) JoinIdentity() (JoinIdentity, bool) {
	if !v.Verified() {
		return JoinIdentity{}, false
	}
	return v.identity, true
}

func (v *VerifiedHistory) MatchesSigner(key *mldsa.PublicKey) bool {
	return v.Verified() && v.policy != nil && v.policy.SignerMatches(key)
}

// VerifyHistoryWithReport returns a deterministic report for both accepted and
// rejected evidence. A failed result never carries a VerifiedHistory token.
func VerifyHistoryWithReport(request Request) (*VerifiedHistory, Report, error) {
	verified, err := VerifyHistory(request)
	if err != nil {
		profile := ""
		if request.Policy != nil {
			profile = request.Policy.Profile()
		}
		report := Report{
			FormatVersion: FormatVersion, Network: request.Network, Node: request.Node, Channel: request.Channel,
			TrustedGenesisBlockIdentity: request.TrustedGenesisHash, TargetBlockNumber: request.TargetBlockNumber,
			RequiredTransportProfile: profile, VerificationResult: "REJECTED", FailureReason: err.Error(),
		}
		return nil, report, err
	}
	return verified, verified.Report(), nil
}

func VerifyHistory(request Request) (*VerifiedHistory, error) {
	if request.Network == "" || request.Node == "" || request.Channel == "" ||
		request.Crypto == nil || request.Policy == nil {
		return nil, errors.New("network, node, channel, crypto provider and authenticated policy are required")
	}
	if err := request.Policy.Check(); err != nil {
		return nil, fmt.Errorf("authenticate local Pactway policy: %w", err)
	}
	if request.Policy.Network() != request.Network || request.Policy.Node() != request.Node ||
		request.Policy.Profile() != pqtransport.ProfileV1 {
		return nil, errors.New("local Pactway policy conflicts with network, node or required transport profile")
	}
	if request.TargetBlockNumber == 0 {
		return nil, errors.New("join-anchor provenance requires a non-genesis target")
	}
	if len(request.History) == 0 || request.TargetBlockNumber >= uint64(len(request.History)) ||
		request.TargetBlockNumber != uint64(len(request.History)-1) {
		return nil, errors.New("history must contain every block from genesis through the exact target")
	}
	history := make([]*cb.Block, len(request.History))
	for index, block := range request.History {
		if block == nil {
			return nil, fmt.Errorf("history block %d is missing", index)
		}
		history[index] = proto.Clone(block).(*cb.Block)
	}
	request.History = history
	trustedGenesis, err := decodeHash(request.TrustedGenesisHash)
	if err != nil {
		return nil, fmt.Errorf("invalid independently trusted genesis identity: %w", err)
	}
	genesis := request.History[0]
	if err := verifyGenesis(genesis, trustedGenesis, request.Channel, request.Crypto); err != nil {
		return nil, fmt.Errorf("verify trusted genesis: %w", err)
	}
	genesisHash := protoutil.BlockHeaderHash(genesis.GetHeader())
	assistant, err := deliverclient.NewBlockVerificationAssistant(genesis, genesis, request.Crypto, flogging.MustGetLogger("pqtransport.provenance"))
	if err != nil {
		return nil, fmt.Errorf("initialize native Fabric block verifier: %w", err)
	}
	genesisConfig, err := configFromBlock(genesis, request.Channel)
	if err != nil {
		return nil, err
	}
	currentBundle, err := channelconfig.NewBundle(request.Channel, genesisConfig.GetConfig(), request.Crypto)
	if err != nil {
		return nil, fmt.Errorf("initialize genesis channel configuration: %w", err)
	}
	if err := currentBundle.ChannelConfig().Capabilities().Supported(); err != nil {
		return nil, fmt.Errorf("unsupported genesis channel capability: %w", err)
	}
	genesisOrderer, hasOrderer := currentBundle.OrdererConfig()
	if !hasOrderer {
		return nil, errors.New("genesis channel configuration has no orderer section")
	}
	if err := etcdraft.ValidateHistoricalConsensusMetadata(nil, genesisOrderer); err != nil {
		return nil, fmt.Errorf("validate genesis consensus metadata: %w", err)
	}
	policyIdentities := make([]PolicyIdentity, 0)
	if identity, err := blockValidationPolicyIdentity(genesis, genesisConfig.GetConfig()); err != nil {
		return nil, err
	} else {
		policyIdentities = append(policyIdentities, identity)
	}

	lastConfigBlock := uint64(0)
	for number := uint64(1); number < uint64(len(request.History)); number++ {
		block := request.History[number]
		if block == nil || block.GetHeader() == nil || block.GetHeader().GetNumber() != number {
			return nil, fmt.Errorf("history block %d is missing or has a conflicting number", number)
		}
		if err := verifyEnvelopeChannels(block, request.Channel); err != nil {
			return nil, fmt.Errorf("verify block %d channel identity: %w", number, err)
		}
		isConfig := protoutil.IsConfigBlock(block)
		expectedLastConfig := lastConfigBlock
		if isConfig {
			expectedLastConfig = number
		}
		if err := verifyLastConfig(block, expectedLastConfig); err != nil {
			return nil, fmt.Errorf("verify block %d last-configuration metadata: %w", number, err)
		}
		if err := assistant.VerifyBlock(block); err != nil {
			return nil, fmt.Errorf("verify Fabric block %d under historical policy: %w", number, err)
		}
		if !isConfig {
			continue
		}

		configEnvelope, err := configFromBlock(block, request.Channel)
		if err != nil {
			return nil, fmt.Errorf("parse configuration block %d: %w", number, err)
		}
		if err := currentBundle.ConfigtxValidator().Validate(configEnvelope); err != nil {
			return nil, fmt.Errorf("authorize configuration block %d under preceding configuration: %w", number, err)
		}
		nextBundle, err := channelconfig.NewBundle(request.Channel, configEnvelope.GetConfig(), request.Crypto)
		if err != nil {
			return nil, fmt.Errorf("load configuration block %d: %w", number, err)
		}
		if err := nextBundle.ChannelConfig().Capabilities().Supported(); err != nil {
			return nil, fmt.Errorf("unsupported channel capability at block %d: %w", number, err)
		}
		if err := currentBundle.ValidateNew(nextBundle); err != nil {
			return nil, fmt.Errorf("validate configuration compatibility at block %d: %w", number, err)
		}
		previousOrderer, hasPreviousOrderer := currentBundle.OrdererConfig()
		nextOrderer, hasNextOrderer := nextBundle.OrdererConfig()
		if !hasPreviousOrderer || !hasNextOrderer {
			return nil, fmt.Errorf("configuration block %d is missing orderer configuration", number)
		}
		if err := etcdraft.ValidateHistoricalConsensusMetadata(previousOrderer, nextOrderer); err != nil {
			return nil, fmt.Errorf("validate consensus metadata at block %d: %w", number, err)
		}
		if identity, err := blockValidationPolicyIdentity(block, configEnvelope.GetConfig()); err != nil {
			return nil, err
		} else {
			policyIdentities = append(policyIdentities, identity)
		}
		if err := assistant.UpdateConfig(block); err != nil {
			return nil, fmt.Errorf("update historical block verifier at block %d: %w", number, err)
		}
		currentBundle = nextBundle
		lastConfigBlock = number
	}

	target := request.History[request.TargetBlockNumber]
	if target == nil || !protoutil.IsConfigBlock(target) {
		return nil, errors.New("unsupported non-configuration target boundary")
	}
	configEnvelope, err := configFromBlock(target, request.Channel)
	if err != nil {
		return nil, err
	}
	encodedConfig, err := (proto.MarshalOptions{Deterministic: true}).Marshal(configEnvelope.GetConfig())
	if err != nil {
		return nil, fmt.Errorf("marshal target configuration deterministically: %w", err)
	}
	configDigest := sha256.Sum256(encodedConfig)
	binding, found := request.Policy.Channel(request.Channel)
	if !found || binding.Sequence != configEnvelope.GetConfig().GetSequence() ||
		binding.Digest != hex.EncodeToString(configDigest[:]) {
		return nil, errors.New("verified Fabric target conflicts with authenticated local Pactway policy checkpoint")
	}
	targetHash := hex.EncodeToString(protoutil.BlockHeaderHash(target.GetHeader()))
	genesisHashHex := hex.EncodeToString(genesisHash)
	identity := JoinIdentity{
		Network: request.Network, Node: request.Node, Profile: request.Policy.Profile(), Channel: request.Channel,
		GenesisHash: genesisHashHex, BlockNumber: request.TargetBlockNumber, BlockHash: targetHash, Config: binding,
	}
	anchorDigest, err := joinAnchorDigest(identity)
	if err != nil {
		return nil, err
	}
	historyIdentity, err := sourceHistoryIdentity(request.History)
	if err != nil {
		return nil, err
	}
	return &VerifiedHistory{
		report: Report{
			FormatVersion: FormatVersion, Network: request.Network, Node: request.Node, Channel: request.Channel,
			TrustedGenesisBlockIdentity: genesisHashHex, SourceHistoryIdentity: historyIdentity,
			VerifiedFromBlock: 0, VerifiedThroughBlock: request.TargetBlockNumber,
			TargetBlockNumber: request.TargetBlockNumber, TargetBlockHash: targetHash,
			TargetConfigurationSequence:  configEnvelope.GetConfig().GetSequence(),
			TargetConfigurationDigest:    hex.EncodeToString(configDigest[:]),
			VerificationPolicyIdentities: policyIdentities, RequiredTransportProfile: request.Policy.Profile(),
			TargetJoinAnchorDigest: anchorDigest, VerificationResult: "PASS",
		},
		target: proto.Clone(target).(*cb.Block), identity: identity, policy: request.Policy, verified: true,
	}, nil
}

func verifyGenesis(block *cb.Block, trustedHash []byte, channel string, crypto bccsp.BCCSP) error {
	if block == nil || block.GetHeader() == nil || block.GetData() == nil ||
		block.GetHeader().GetNumber() != 0 || len(block.GetHeader().GetPreviousHash()) != 0 {
		return errors.New("invalid genesis block shape")
	}
	dataHash, err := protoutil.BlockDataHash(block.GetData())
	if err != nil {
		return fmt.Errorf("verify genesis data: %w", err)
	}
	if !bytes.Equal(dataHash, block.GetHeader().GetDataHash()) ||
		!bytes.Equal(protoutil.BlockHeaderHash(block.GetHeader()), trustedHash) {
		return errors.New("genesis content does not match independently trusted identity")
	}
	configEnvelope, err := configFromBlock(block, channel)
	if err != nil {
		return err
	}
	if configEnvelope.GetConfig().GetSequence() != 0 {
		return errors.New("genesis configuration sequence must be zero")
	}
	if err := verifyLastConfig(block, 0); err != nil {
		return err
	}
	if _, err := channelconfig.NewBundle(channel, configEnvelope.GetConfig(), crypto); err != nil {
		return fmt.Errorf("validate genesis channel configuration: %w", err)
	}
	return nil
}

func configFromBlock(block *cb.Block, channel string) (*cb.ConfigEnvelope, error) {
	if block == nil || !protoutil.IsConfigBlock(block) || len(block.GetData().GetData()) != 1 {
		return nil, errors.New("configuration block must contain exactly one configuration envelope")
	}
	envelope, err := protoutil.ExtractEnvelope(block, 0)
	if err != nil {
		return nil, err
	}
	config := &cb.ConfigEnvelope{}
	header, err := protoutil.UnmarshalEnvelopeOfType(envelope, cb.HeaderType_CONFIG, config)
	if err != nil {
		return nil, err
	}
	if header.GetChannelId() != channel || config.GetConfig() == nil {
		return nil, errors.New("configuration block channel or config conflicts with expected identity")
	}
	return config, nil
}

func verifyEnvelopeChannels(block *cb.Block, channel string) error {
	for index := range block.GetData().GetData() {
		envelope, err := protoutil.ExtractEnvelope(block, index)
		if err != nil {
			return err
		}
		payload, err := protoutil.UnmarshalPayload(envelope.GetPayload())
		if err != nil {
			return err
		}
		if payload.GetHeader() == nil {
			return errors.New("transaction is missing its payload header")
		}
		channelHeader, err := protoutil.UnmarshalChannelHeader(payload.GetHeader().GetChannelHeader())
		if err != nil {
			return err
		}
		if channelHeader.GetChannelId() != channel {
			return fmt.Errorf("transaction channel %q does not match %q", channelHeader.GetChannelId(), channel)
		}
	}
	return nil
}

func verifyLastConfig(block *cb.Block, expected uint64) error {
	signedIndex, err := protoutil.GetLastConfigIndexFromBlock(block)
	if err != nil {
		return err
	}
	if signedIndex != expected {
		return fmt.Errorf("signed last-config index is %d, expected %d", signedIndex, expected)
	}
	metadata, err := protoutil.GetMetadataFromBlock(block, cb.BlockMetadataIndex_LAST_CONFIG)
	if err != nil {
		return err
	}
	lastConfig := &cb.LastConfig{}
	if err := proto.Unmarshal(metadata.GetValue(), lastConfig); err != nil {
		return fmt.Errorf("unmarshal LAST_CONFIG value: %w", err)
	}
	if lastConfig.GetIndex() != signedIndex {
		return fmt.Errorf("LAST_CONFIG index %d conflicts with signed index %d", lastConfig.GetIndex(), signedIndex)
	}
	return nil
}

func blockValidationPolicyIdentity(block *cb.Block, config *cb.Config) (PolicyIdentity, error) {
	ordererGroup := config.GetChannelGroup().GetGroups()["Orderer"]
	if ordererGroup == nil {
		return PolicyIdentity{}, errors.New("channel configuration has no orderer group")
	}
	policy := ordererGroup.GetPolicies()["BlockValidation"]
	if policy == nil || policy.GetPolicy() == nil {
		return PolicyIdentity{}, errors.New("channel configuration has no BlockValidation policy")
	}
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(policy.GetPolicy())
	if err != nil {
		return PolicyIdentity{}, err
	}
	digest := sha256.Sum256(encoded)
	encodedConfig, err := (proto.MarshalOptions{Deterministic: true}).Marshal(config)
	if err != nil {
		return PolicyIdentity{}, err
	}
	configDigest := sha256.Sum256(encodedConfig)
	return PolicyIdentity{
		ConfigBlockNumber: block.GetHeader().GetNumber(), ConfigSequence: config.GetSequence(),
		ConfigurationDigest: hex.EncodeToString(configDigest[:]), PolicyDigest: hex.EncodeToString(digest[:]),
	}, nil
}

func decodeHash(value string) ([]byte, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != value {
		return nil, errors.New("expected lowercase SHA-256 hex")
	}
	return decoded, nil
}

func sourceHistoryIdentity(history []*cb.Block) (string, error) {
	hash := sha256.New()
	var length [8]byte
	for _, block := range history {
		encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(block)
		if err != nil {
			return "", fmt.Errorf("marshal source history block: %w", err)
		}
		binary.BigEndian.PutUint64(length[:], uint64(len(encoded)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write(encoded)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func joinAnchorDigest(identity JoinIdentity) (string, error) {
	anchor := struct {
		Network     string                     `json:"network"`
		Node        string                     `json:"node"`
		Profile     string                     `json:"profile"`
		Channel     string                     `json:"channel"`
		GenesisHash string                     `json:"genesis_hash"`
		BlockNumber uint64                     `json:"block_number"`
		BlockHash   string                     `json:"block_hash"`
		Config      pqtransport.ChannelBinding `json:"config"`
	}{
		identity.Network, identity.Node, identity.Profile, identity.Channel,
		identity.GenesisHash, identity.BlockNumber, identity.BlockHash, identity.Config,
	}
	encoded, err := json.Marshal(anchor)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}
