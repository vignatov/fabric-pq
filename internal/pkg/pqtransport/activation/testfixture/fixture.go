/*
SPDX-License-Identifier: Apache-2.0
*/

// Package testfixture builds a real Fabric policy update and an independent
// operator authorization for the activation tests.
package testfixture

import (
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/hyperledger/fabric-lib-go/bccsp"
	"github.com/hyperledger/fabric-lib-go/bccsp/sw"
	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	ab "github.com/hyperledger/fabric-protos-go-apiv2/orderer"
	"github.com/hyperledger/fabric/common/capabilities"
	"github.com/hyperledger/fabric/common/channelconfig"
	configtxtest "github.com/hyperledger/fabric/common/configtx/test"
	"github.com/hyperledger/fabric/common/util"
	"github.com/hyperledger/fabric/core/config/configtest"
	"github.com/hyperledger/fabric/internal/configtxlator/update"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/enrollment"
	"github.com/hyperledger/fabric/msp"
	"github.com/hyperledger/fabric/protoutil"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

const (
	Network   = "proof-network"
	Node      = "proof-node"
	ChannelID = "activation-proof"
)

type Fixture struct {
	Crypto bccsp.BCCSP
	Fabric msp.SigningIdentity
	key    *mldsa.PrivateKey
}

func New(t *testing.T) Fixture {
	t.Helper()
	dir := configtest.GetDevMspDir()
	keystore, err := sw.NewFileBasedKeyStore(nil, filepath.Join(dir, "keystore"), true)
	require.NoError(t, err)
	crypto, err := sw.NewDefaultSecurityLevelWithKeystore(keystore)
	require.NoError(t, err)
	config, err := msp.GetLocalMspConfig(dir, nil, "SampleOrg")
	require.NoError(t, err)
	opts := &msp.BCCSPNewOpts{}
	opts.Version = msp.MSPv3_0
	local, err := msp.New(opts, crypto)
	require.NoError(t, err)
	require.NoError(t, local.Setup(config))
	signer, err := local.GetDefaultSigningIdentity()
	require.NoError(t, err)
	// The fixed, test-only seed gives the subprocess the same trust anchor.
	seed := sha256.Sum256([]byte("PQ4.0C activation fixture operator"))
	key, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), seed[:])
	require.NoError(t, err)
	return Fixture{Crypto: crypto, Fabric: signer, key: key}
}

func (f Fixture) Channel(store *activation.Store, ledger activation.Ledger) activation.Channel {
	return activation.Channel{
		Store: store, Gate: &activation.Gate{}, Ledger: ledger, Network: Network, Node: Node,
		ID: ChannelID, Signer: f.key.Public().(*mldsa.PublicKey), Crypto: f.Crypto,
	}
}

func Genesis(t *testing.T) *cb.Block {
	t.Helper()
	block, err := configtxtest.MakeGenesisBlock(ChannelID)
	require.NoError(t, err)
	return block
}

// TransportGenesis makes a fresh test genesis declaring the real capability.
func TransportGenesis(t *testing.T) *cb.Block {
	t.Helper()
	block := Genesis(t)
	envelope, err := protoutil.ExtractEnvelope(block, 0)
	require.NoError(t, err)
	payload, err := protoutil.UnmarshalPayload(envelope.GetPayload())
	require.NoError(t, err)
	config := &cb.ConfigEnvelope{}
	require.NoError(t, proto.Unmarshal(payload.GetData(), config))
	group := config.GetConfig().GetChannelGroup()
	value := group.GetValues()[channelconfig.CapabilitiesKey]
	if value == nil {
		value = &cb.ConfigValue{}
		group.Values[channelconfig.CapabilitiesKey] = value
	}
	caps := &cb.Capabilities{}
	if len(value.Value) != 0 {
		require.NoError(t, proto.Unmarshal(value.Value, caps))
	}
	if caps.Capabilities == nil {
		caps.Capabilities = make(map[string]*cb.Capability)
	}
	caps.Capabilities[capabilities.PactwayPQTransportV1] = &cb.Capability{}
	value.Value = protoutil.MarshalOrPanic(caps)
	payload.Data = protoutil.MarshalOrPanic(config)
	envelope.Payload = protoutil.MarshalOrPanic(payload)
	block.Data.Data[0] = protoutil.MarshalOrPanic(envelope)
	block.Header.DataHash = protoutil.ComputeBlockDataHash(block.Data)
	return block
}

func Config(t *testing.T, block *cb.Block) *cb.Config {
	t.Helper()
	env, err := protoutil.ExtractEnvelope(block, 0)
	require.NoError(t, err)
	config := &cb.ConfigEnvelope{}
	_, err = protoutil.UnmarshalEnvelopeOfType(env, cb.HeaderType_CONFIG, config)
	require.NoError(t, err)
	return config.GetConfig()
}

func (f Fixture) Update(t *testing.T, base *cb.Config) *cb.ConfigEnvelope {
	t.Helper()
	next := proto.CloneOf(base)
	value := next.GetChannelGroup().GetGroups()["Orderer"].GetValues()["BatchSize"]
	batch := &ab.BatchSize{}
	require.NoError(t, proto.Unmarshal(value.GetValue(), batch))
	batch.AbsoluteMaxBytes++
	value.Value = protoutil.MarshalOrPanic(batch)
	return f.UpdateTo(t, base, next)
}

// UpdateTo signs and validates the difference between two test configurations.
func (f Fixture) UpdateTo(t *testing.T, base, next *cb.Config) *cb.ConfigEnvelope {
	t.Helper()
	return f.UpdateChannelTo(t, ChannelID, base, next)
}

// UpdateChannelTo signs and validates a configuration update for the given channel.
func (f Fixture) UpdateChannelTo(t *testing.T, channel string, base, next *cb.Config) *cb.ConfigEnvelope {
	t.Helper()
	update, err := update.Compute(base, next)
	require.NoError(t, err)
	update.ChannelId = channel
	header, err := protoutil.NewSignatureHeader(f.Fabric)
	require.NoError(t, err)
	updateBytes := protoutil.MarshalOrPanic(update)
	signatureHeader := protoutil.MarshalOrPanic(header)
	signature, err := f.Fabric.Sign(util.ConcatenateBytes(signatureHeader, updateBytes))
	require.NoError(t, err)
	envelope, err := protoutil.CreateSignedEnvelope(cb.HeaderType_CONFIG_UPDATE, channel, f.Fabric, &cb.ConfigUpdateEnvelope{
		ConfigUpdate: updateBytes,
		Signatures:   []*cb.ConfigSignature{{SignatureHeader: signatureHeader, Signature: signature}},
	}, 0, 0)
	require.NoError(t, err)
	bundle, err := channelconfig.NewBundle(channel, base, f.Crypto)
	require.NoError(t, err)
	config, err := bundle.ConfigtxValidator().ProposeConfigUpdate(envelope)
	require.NoError(t, err)
	return config
}

func (f Fixture) Envelope(t *testing.T, config *cb.ConfigEnvelope) *cb.Envelope {
	t.Helper()
	envelope, err := protoutil.CreateSignedEnvelope(cb.HeaderType_CONFIG, ChannelID, f.Fabric, config, 0, 0)
	require.NoError(t, err)
	return envelope
}

func (f Fixture) Provision(t *testing.T, store *activation.Store, config *cb.Config) {
	t.Helper()
	payload, signature := f.sign(t, document(t, 1, config))
	require.NoError(t, store.Provision(pqtransport.Checkpoint{Version: 1, Digest: sha256.Sum256(payload)}, payload, signature))
}

func (f Fixture) Authorize(t *testing.T, version uint64, base, next *cb.Config) activation.Authorization {
	t.Helper()
	previous, err := json.Marshal(document(t, version, base))
	require.NoError(t, err)
	candidate := document(t, version+1, next)
	payload, signature := f.sign(t, candidate)
	transition, transitionSignature := f.sign(t, pqtransport.TransitionDocument{
		Network: Network, Node: Node, Channel: ChannelID, Profile: pqtransport.ProfileV1,
		PreviousVersion: version, PreviousDigest: digest(previous),
		NewVersion: version + 1, NewPolicyDigest: digest(payload),
		NewConfigSequence: next.GetSequence(), NewConfigDigest: candidate.Channels[ChannelID].Digest,
	})
	return activation.Authorization{
		Transition: transition, TransitionSignature: transitionSignature,
		Policy: payload, PolicySignature: signature,
	}
}

func document(t *testing.T, version uint64, config *cb.Config) pqtransport.Document {
	t.Helper()
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(config)
	require.NoError(t, err)
	return pqtransport.Document{
		Network: Network, Node: Node, Version: version, Profile: pqtransport.ProfileV1,
		Channels: map[string]pqtransport.ChannelBinding{ChannelID: {Sequence: config.GetSequence(), Digest: digest(encoded)}},
	}
}

func digest(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func (f Fixture) sign(t *testing.T, document any) ([]byte, []byte) {
	t.Helper()
	payload, err := json.Marshal(document)
	require.NoError(t, err)
	signature, err := f.key.Sign(rand.Reader, payload, nil)
	require.NoError(t, err)
	return payload, signature
}

func (f Fixture) JoinAnchor(t *testing.T, genesis, block *cb.Block) enrollment.JoinAnchor {
	t.Helper()
	conf := Config(t, block)
	return enrollment.JoinAnchor{
		Network: Network, Node: Node, Profile: pqtransport.ProfileV1, Channel: ChannelID,
		GenesisHash: hex.EncodeToString(protoutil.BlockHeaderHash(genesis.GetHeader())),
		BlockNumber: block.GetHeader().GetNumber(),
		BlockHash:   hex.EncodeToString(protoutil.BlockHeaderHash(block.GetHeader())),
		Config:      document(t, 1, conf).Channels[ChannelID],
	}
}

func (f Fixture) SignedJoinAnchor(t *testing.T, domain string, anchor any) []byte {
	t.Helper()
	payload, err := json.Marshal(anchor)
	require.NoError(t, err)
	signature, err := f.key.Sign(rand.Reader, append([]byte(domain), payload...), nil)
	require.NoError(t, err)
	encoded, err := json.Marshal(enrollment.Envelope{Payload: payload, Signature: signature})
	require.NoError(t, err)
	return encoded
}
