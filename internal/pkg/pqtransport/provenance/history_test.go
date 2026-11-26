/*
SPDX-License-Identifier: Apache-2.0
*/

package provenance_test

import (
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	mspproto "github.com/hyperledger/fabric-protos-go-apiv2/msp"
	ordererproto "github.com/hyperledger/fabric-protos-go-apiv2/orderer"
	"github.com/hyperledger/fabric/common/util"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation/testfixture"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/enrollment"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/provenance"
	"github.com/hyperledger/fabric/protoutil"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestVerifyHistoryFromTrustedGenesisThroughConfigurationTransitions(t *testing.T) {
	fixture := testfixture.New(t)
	genesis := fixture.RaftGenesis(t)
	base := testfixture.Config(t, genesis)
	config1 := fixture.Update(t, base)
	configBlock1 := appendBlock(t, fixture, genesis, fixture.Envelope(t, config1), 1)
	normalBlock := appendBlock(t, fixture, configBlock1, messageEnvelope(t, fixture), 1)
	config2 := fixture.Update(t, config1.GetConfig())
	configBlock2 := appendBlock(t, fixture, normalBlock, fixture.Envelope(t, config2), 3)
	history := []*common.Block{genesis, configBlock1, normalBlock, configBlock2}
	request := verificationRequest(t, history, configBlock2, config2.GetConfig())

	verified, err := provenance.VerifyHistory(request)
	require.NoError(t, err)
	require.True(t, verified.Verified())
	report := verified.Report()
	require.Equal(t, provenance.FormatVersion, report.FormatVersion)
	require.Equal(t, testfixture.Network, report.Network)
	require.Equal(t, testfixture.Node, report.Node)
	require.Equal(t, testfixture.ChannelID, report.Channel)
	require.Equal(t, uint64(0), report.VerifiedFromBlock)
	require.Equal(t, uint64(3), report.VerifiedThroughBlock)
	require.Equal(t, uint64(2), report.TargetConfigurationSequence)
	require.Len(t, report.VerificationPolicyIdentities, 3)
	require.Equal(t, "PASS", report.VerificationResult)

	identity, ok := verified.JoinIdentity()
	require.True(t, ok)
	anchor := enrollment.JoinAnchor{
		Network: identity.Network, Node: identity.Node, Profile: identity.Profile, Channel: identity.Channel,
		GenesisHash: identity.GenesisHash, BlockNumber: identity.BlockNumber, BlockHash: identity.BlockHash,
		Config: identity.Config,
	}
	encodedAnchor, err := json.Marshal(anchor)
	require.NoError(t, err)
	digest := sha256.Sum256(encodedAnchor)
	require.Equal(t, hex.EncodeToString(digest[:]), report.TargetJoinAnchorDigest)
	require.True(t, proto.Equal(configBlock2, verified.TargetBlock()))

	// Report and target accessors return copies so callers cannot mutate the verified result.
	report.VerificationPolicyIdentities[0].PolicyDigest = "tampered"
	reportAgain := verified.Report()
	require.NotEqual(t, "tampered", reportAgain.VerificationPolicyIdentities[0].PolicyDigest)
	target := verified.TargetBlock()
	target.Header.DataHash[0] ^= 0xff
	require.True(t, proto.Equal(configBlock2, verified.TargetBlock()))
}

func TestVerifyHistoryRejectsUnsupportedConsensusWithoutMetadata(t *testing.T) {
	fixture := testfixture.New(t)
	genesis := testfixture.Genesis(t)
	consensus := &ordererproto.ConsensusType{}
	require.NoError(t, proto.Unmarshal(testfixture.Config(t, genesis).GetChannelGroup().GetGroups()["Orderer"].GetValues()["ConsensusType"].GetValue(), consensus))
	require.NotEqual(t, "etcdraft", consensus.GetType())
	require.Empty(t, consensus.GetMetadata())
	config := fixture.Update(t, testfixture.Config(t, genesis))
	target := fixture.SignedBlock(t, genesis, fixture.Envelope(t, config), 1)
	request := verificationRequest(t, []*common.Block{genesis, target}, target, config.GetConfig())
	verified, err := provenance.VerifyHistory(request)
	require.Nil(t, verified)
	require.ErrorContains(t, err, "only Raft consensus is supported")
}

func TestVerifyHistoryRejectsIncompleteOrUnauthorisedEvidence(t *testing.T) {
	fixture := testfixture.New(t)
	genesis := fixture.RaftGenesis(t)
	base := testfixture.Config(t, genesis)
	config1 := fixture.Update(t, base)
	configBlock1 := appendBlock(t, fixture, genesis, fixture.Envelope(t, config1), 1)
	normalBlock := appendBlock(t, fixture, configBlock1, messageEnvelope(t, fixture), 1)
	config2 := fixture.Update(t, config1.GetConfig())
	configBlock2 := appendBlock(t, fixture, normalBlock, fixture.Envelope(t, config2), 3)
	history := []*common.Block{genesis, configBlock1, normalBlock, configBlock2}

	tests := []struct {
		name    string
		mutate  func(*testing.T, provenance.Request) provenance.Request
		wantErr string
	}{
		{
			name: "wrong trusted genesis",
			mutate: func(t *testing.T, request provenance.Request) provenance.Request {
				request.TrustedGenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"
				return request
			},
			wantErr: "trusted identity",
		},
		{
			name: "missing intermediate block",
			mutate: func(t *testing.T, request provenance.Request) provenance.Request {
				request.History = []*common.Block{history[0], history[1], history[3]}
				request.TargetBlockNumber = 2
				return request
			},
			wantErr: "conflicting number",
		},
		{
			name: "broken previous hash",
			mutate: func(t *testing.T, request provenance.Request) provenance.Request {
				request.History = cloneHistory(t, request.History)
				request.History[2].Header.PreviousHash[0] ^= 0xff
				return request
			},
			wantErr: "PreviousHash",
		},
		{
			name: "invalid block signature",
			mutate: func(t *testing.T, request provenance.Request) provenance.Request {
				request.History = cloneHistory(t, request.History)
				signatures, err := protoutil.GetMetadataFromBlock(request.History[2], common.BlockMetadataIndex_SIGNATURES)
				require.NoError(t, err)
				signatures.Signatures[0].Signature[0] ^= 0xff
				request.History[2].Metadata.Metadata[common.BlockMetadataIndex_SIGNATURES] = protoutil.MarshalOrPanic(signatures)
				return request
			},
			wantErr: "policy evaluation failed",
		},
		{
			name: "valid signature under an unauthorised MSP identity",
			mutate: func(t *testing.T, request provenance.Request) provenance.Request {
				request.History = cloneHistory(t, request.History)
				block := request.History[2]
				signatures, err := protoutil.GetMetadataFromBlock(block, common.BlockMetadataIndex_SIGNATURES)
				require.NoError(t, err)
				signatureHeader := &common.SignatureHeader{}
				require.NoError(t, proto.Unmarshal(signatures.GetSignatures()[0].GetSignatureHeader(), signatureHeader))
				creator := &mspproto.SerializedIdentity{}
				require.NoError(t, proto.Unmarshal(signatureHeader.GetCreator(), creator))
				creator.Mspid = "UnauthorisedMSP"
				signatureHeader.Creator = protoutil.MarshalOrPanic(creator)
				signatureHeaderBytes := protoutil.MarshalOrPanic(signatureHeader)
				signature, err := fixture.Fabric.Sign(util.ConcatenateBytes(
					signatures.GetValue(), signatureHeaderBytes, protoutil.BlockHeaderBytes(block.GetHeader()),
				))
				require.NoError(t, err)
				signatures.Signatures[0].SignatureHeader = signatureHeaderBytes
				signatures.Signatures[0].Signature = signature
				block.Metadata.Metadata[common.BlockMetadataIndex_SIGNATURES] = protoutil.MarshalOrPanic(signatures)
				return request
			},
			wantErr: "policy evaluation failed",
		},
		{
			name: "unauthorised historical configuration transition",
			mutate: func(t *testing.T, request provenance.Request) provenance.Request {
				request.History = cloneHistory(t, request.History)
				configEnvelope := &common.ConfigEnvelope{}
				_, err := protoutil.UnmarshalEnvelopeOfType(mustEnvelope(t, request.History[1]), common.HeaderType_CONFIG, configEnvelope)
				require.NoError(t, err)
				payload, err := protoutil.UnmarshalPayload(configEnvelope.GetLastUpdate().GetPayload())
				require.NoError(t, err)
				updateEnvelope := &common.ConfigUpdateEnvelope{}
				require.NoError(t, proto.Unmarshal(payload.GetData(), updateEnvelope))
				updateEnvelope.Signatures[0].Signature[0] ^= 0xff
				payload.Data = protoutil.MarshalOrPanic(updateEnvelope)
				configEnvelope.LastUpdate.Payload = protoutil.MarshalOrPanic(payload)
				updatedBlockEnvelope, err := protoutil.CreateSignedEnvelope(common.HeaderType_CONFIG, testfixture.ChannelID, fixture.Fabric, configEnvelope, 0, 0)
				require.NoError(t, err)
				request.History[1] = replaceEnvelope(t, fixture, request.History[1], updatedBlockEnvelope, 1)
				return request
			},
			wantErr: "authorize configuration block",
		},
		{
			name: "wrong channel identity",
			mutate: func(t *testing.T, request provenance.Request) provenance.Request {
				request.History = cloneHistory(t, request.History)
				wrongChannelEnvelope, err := protoutil.CreateSignedEnvelope(common.HeaderType_CONFIG, "other-channel", fixture.Fabric, mustConfigEnvelope(t, request.History[3]), 0, 0)
				require.NoError(t, err)
				request.History[3] = replaceEnvelope(t, fixture, request.History[3], wrongChannelEnvelope, 3)
				return request
			},
			wantErr: "channel identity",
		},
		{
			name: "wrong local policy checkpoint",
			mutate: func(t *testing.T, request provenance.Request) provenance.Request {
				request.Policy = authenticatedPolicy(t, fixture, config1.GetConfig())
				return request
			},
			wantErr: "conflicts with authenticated local",
		},
		{
			name: "unsupported non-configuration target",
			mutate: func(t *testing.T, request provenance.Request) provenance.Request {
				request.History = request.History[:3]
				request.TargetBlockNumber = 2
				request.Policy = authenticatedPolicy(t, fixture, config1.GetConfig())
				return request
			},
			wantErr: "unsupported non-configuration target",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := verificationRequest(t, history, configBlock2, config2.GetConfig())
			request = test.mutate(t, request)
			verified, report, err := provenance.VerifyHistoryWithReport(request)
			require.ErrorContains(t, err, test.wantErr)
			require.Nil(t, verified)
			require.Equal(t, "REJECTED", report.VerificationResult)
			require.Equal(t, err.Error(), report.FailureReason)
		})
	}
}

func verificationRequest(t *testing.T, history []*common.Block, target *common.Block, config *common.Config) provenance.Request {
	t.Helper()
	fixture := testfixture.New(t)
	return provenance.Request{
		Network: testfixture.Network, Node: testfixture.Node, Channel: testfixture.ChannelID,
		TrustedGenesisHash: hex.EncodeToString(protoutil.BlockHeaderHash(history[0].GetHeader())),
		TargetBlockNumber:  target.GetHeader().GetNumber(), History: history,
		Policy: authenticatedPolicy(t, fixture, config), Crypto: fixture.Crypto,
	}
}

func authenticatedPolicy(t *testing.T, fixture testfixture.Fixture, config *common.Config) *pqtransport.Policy {
	t.Helper()
	encodedConfig, err := (proto.MarshalOptions{Deterministic: true}).Marshal(config)
	require.NoError(t, err)
	configDigest := sha256.Sum256(encodedConfig)
	document := pqtransport.Document{
		Network: testfixture.Network, Node: testfixture.Node, Version: 1, Profile: pqtransport.ProfileV1,
		Channels: map[string]pqtransport.ChannelBinding{
			testfixture.ChannelID: {Sequence: config.GetSequence(), Digest: hex.EncodeToString(configDigest[:])},
		},
	}
	payload, err := json.Marshal(document)
	require.NoError(t, err)
	seed := sha256.Sum256([]byte("PQ4.0E.1 provenance test signer"))
	key, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), seed[:])
	require.NoError(t, err)
	signature, err := key.Sign(rand.Reader, payload, nil)
	require.NoError(t, err)
	checkpointDigest := sha256.Sum256(payload)
	policy, err := pqtransport.Authenticate(
		payload, signature, key.Public().(*mldsa.PublicKey),
		&pqtransport.Checkpoint{Version: document.Version, Digest: checkpointDigest},
		testfixture.Network, testfixture.Node,
	)
	require.NoError(t, err)
	return policy
}

func appendBlock(t *testing.T, fixture testfixture.Fixture, previous *common.Block, envelope *common.Envelope, lastConfig uint64) *common.Block {
	t.Helper()
	return fixture.SignedBlock(t, previous, envelope, lastConfig)
}

func messageEnvelope(t *testing.T, fixture testfixture.Fixture) *common.Envelope {
	t.Helper()
	envelope, err := protoutil.CreateSignedEnvelope(common.HeaderType_MESSAGE, testfixture.ChannelID, fixture.Fabric, &common.Config{}, 0, 0)
	require.NoError(t, err)
	return envelope
}

func replaceEnvelope(t *testing.T, fixture testfixture.Fixture, previous *common.Block, envelope *common.Envelope, lastConfig uint64) *common.Block {
	t.Helper()
	block := protoutil.NewBlock(previous.GetHeader().GetNumber(), previous.GetHeader().GetPreviousHash())
	block.Data.Data = [][]byte{protoutil.MarshalOrPanic(envelope)}
	block.Header.DataHash = protoutil.ComputeBlockDataHash(block.GetData())
	protoutil.InitBlockMetadata(block)

	lastConfigBytes := protoutil.MarshalOrPanic(&common.LastConfig{Index: lastConfig})
	ordererMetadata := protoutil.MarshalOrPanic(&common.OrdererBlockMetadata{LastConfig: &common.LastConfig{Index: lastConfig}})
	signatureHeader, err := protoutil.NewSignatureHeader(fixture.Fabric)
	require.NoError(t, err)
	signatureHeaderBytes := protoutil.MarshalOrPanic(signatureHeader)
	signature, err := fixture.Fabric.Sign(util.ConcatenateBytes(ordererMetadata, signatureHeaderBytes, protoutil.BlockHeaderBytes(block.GetHeader())))
	require.NoError(t, err)
	block.Metadata.Metadata[common.BlockMetadataIndex_SIGNATURES] = protoutil.MarshalOrPanic(&common.Metadata{
		Value: ordererMetadata,
		Signatures: []*common.MetadataSignature{{
			SignatureHeader: signatureHeaderBytes,
			Signature:       signature,
		}},
	})
	block.Metadata.Metadata[common.BlockMetadataIndex_LAST_CONFIG] = protoutil.MarshalOrPanic(&common.Metadata{Value: lastConfigBytes})
	return block
}

func mustEnvelope(t *testing.T, block *common.Block) *common.Envelope {
	t.Helper()
	envelope, err := protoutil.ExtractEnvelope(block, 0)
	require.NoError(t, err)
	return envelope
}

func mustConfigEnvelope(t *testing.T, block *common.Block) *common.ConfigEnvelope {
	t.Helper()
	config := &common.ConfigEnvelope{}
	_, err := protoutil.UnmarshalEnvelopeOfType(mustEnvelope(t, block), common.HeaderType_CONFIG, config)
	require.NoError(t, err)
	return config
}

func cloneHistory(t *testing.T, history []*common.Block) []*common.Block {
	t.Helper()
	cloned := make([]*common.Block, len(history))
	for index, block := range history {
		cloned[index] = proto.Clone(block).(*common.Block)
	}
	return cloned
}
