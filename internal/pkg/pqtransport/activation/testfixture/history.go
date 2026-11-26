/*
SPDX-License-Identifier: Apache-2.0
*/

package testfixture

import (
	"testing"

	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	mb "github.com/hyperledger/fabric-protos-go-apiv2/msp"
	ab "github.com/hyperledger/fabric-protos-go-apiv2/orderer"
	rb "github.com/hyperledger/fabric-protos-go-apiv2/orderer/etcdraft"
	"github.com/hyperledger/fabric/common/crypto/tlsgen"
	"github.com/hyperledger/fabric/common/util"
	"github.com/hyperledger/fabric/protoutil"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// RaftGenesis creates an independently rooted Fabric Raft configuration.
func (f Fixture) RaftGenesis(t *testing.T) *cb.Block {
	t.Helper()
	genesis := Genesis(t)
	config := Config(t, genesis)
	ca, err := tlsgen.NewCA()
	require.NoError(t, err)
	server, err := ca.NewServerCertKeyPair("127.0.0.1")
	require.NoError(t, err)
	client, err := ca.NewClientCertKeyPair()
	require.NoError(t, err)
	orderer := config.GetChannelGroup().GetGroups()["Orderer"]
	var addRoot func(*cb.ConfigGroup)
	addRoot = func(group *cb.ConfigGroup) {
		if value := group.GetValues()["MSP"]; value != nil {
			wrapper := &mb.MSPConfig{}
			require.NoError(t, proto.Unmarshal(value.GetValue(), wrapper))
			mspConfig := &mb.FabricMSPConfig{}
			require.NoError(t, proto.Unmarshal(wrapper.GetConfig(), mspConfig))
			mspConfig.TlsRootCerts = append(mspConfig.GetTlsRootCerts(), ca.CertBytes())
			wrapper.Config = protoutil.MarshalOrPanic(mspConfig)
			value.Value = protoutil.MarshalOrPanic(wrapper)
		}
		for _, child := range group.GetGroups() {
			addRoot(child)
		}
	}
	addRoot(config.GetChannelGroup())
	metadata := &rb.ConfigMetadata{
		Consenters: []*rb.Consenter{{
			Host: "127.0.0.1", Port: 7050,
			ServerTlsCert: server.Cert, ClientTlsCert: client.Cert,
		}},
		Options: &rb.Options{TickInterval: "10ms", HeartbeatTick: 1, ElectionTick: 10, MaxInflightBlocks: 4},
	}
	orderer.GetValues()["ConsensusType"].Value = protoutil.MarshalOrPanic(
		&ab.ConsensusType{Type: "etcdraft", Metadata: protoutil.MarshalOrPanic(metadata)},
	)
	genesis.Data.Data[0] = protoutil.MarshalOrPanic(f.Envelope(t, &cb.ConfigEnvelope{Config: config}))
	genesis.Header.DataHash = protoutil.ComputeBlockDataHash(genesis.GetData())
	return genesis
}

// SignedBlock builds a block signed by the fixture's Fabric orderer identity.
func (f Fixture) SignedBlock(t *testing.T, previous *cb.Block, envelope *cb.Envelope, lastConfig uint64) *cb.Block {
	t.Helper()
	block := protoutil.NewBlock(previous.GetHeader().GetNumber()+1, protoutil.BlockHeaderHash(previous.GetHeader()))
	block.Data.Data = [][]byte{protoutil.MarshalOrPanic(envelope)}
	block.Header.DataHash = protoutil.ComputeBlockDataHash(block.GetData())
	protoutil.InitBlockMetadata(block)
	ordererMetadata := protoutil.MarshalOrPanic(&cb.OrdererBlockMetadata{LastConfig: &cb.LastConfig{Index: lastConfig}})
	signatureHeader, err := protoutil.NewSignatureHeader(f.Fabric)
	require.NoError(t, err)
	signatureHeaderBytes := protoutil.MarshalOrPanic(signatureHeader)
	signature, err := f.Fabric.Sign(util.ConcatenateBytes(ordererMetadata, signatureHeaderBytes, protoutil.BlockHeaderBytes(block.GetHeader())))
	require.NoError(t, err)
	block.Metadata.Metadata[cb.BlockMetadataIndex_SIGNATURES] = protoutil.MarshalOrPanic(&cb.Metadata{
		Value: ordererMetadata,
		Signatures: []*cb.MetadataSignature{{
			SignatureHeader: signatureHeaderBytes,
			Signature:       signature,
		}},
	})
	block.Metadata.Metadata[cb.BlockMetadataIndex_LAST_CONFIG] = protoutil.MarshalOrPanic(&cb.Metadata{
		Value: protoutil.MarshalOrPanic(&cb.LastConfig{Index: lastConfig}),
	})
	return block
}
