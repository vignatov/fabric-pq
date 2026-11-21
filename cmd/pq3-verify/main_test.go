/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-protos-go-apiv2/ledger/rwset"
	"github.com/hyperledger/fabric-protos-go-apiv2/ledger/rwset/kvrwset"
	mspprotos "github.com/hyperledger/fabric-protos-go-apiv2/msp"
	peer "github.com/hyperledger/fabric-protos-go-apiv2/peer"
	"github.com/hyperledger/fabric/common/capabilities"
	oqs "github.com/hyperledger/fabric/pq-crypto"
	"github.com/hyperledger/fabric/protoutil"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestFindCommittedTransactionRequiresExactValidTransaction(t *testing.T) {
	tests := []struct {
		name        string
		filter      []byte
		txID        string
		wantErr     string
		wantTxIndex int
	}{
		{
			name:        "valid exact transaction",
			filter:      []byte{byte(peer.TxValidationCode_VALID)},
			txID:        "target-tx",
			wantTxIndex: 0,
		},
		{
			name:    "missing validation filter",
			txID:    "target-tx",
			wantErr: "no transaction validation filter",
		},
		{
			name:    "invalid transaction",
			filter:  []byte{byte(peer.TxValidationCode_ENDORSEMENT_POLICY_FAILURE)},
			txID:    "target-tx",
			wantErr: "validation code ENDORSEMENT_POLICY_FAILURE",
		},
		{
			name:    "unrelated transaction",
			filter:  []byte{byte(peer.TxValidationCode_VALID)},
			txID:    "other-tx",
			wantErr: "is not present",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			envelope := testEnvelope(t, "target-tx")
			block := testBlock(envelope, test.filter)
			found, index, err := findCommittedTransaction(block, test.txID)
			if test.wantErr != "" {
				require.ErrorContains(t, err, test.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.wantTxIndex, index)
			require.True(t, proto.Equal(envelope, found))
		})
	}
}

func TestValidateProcessedTransactionBindsPeerValidationAndEnvelope(t *testing.T) {
	envelope := testEnvelope(t, "target-tx")
	tests := []struct {
		name     string
		txID     string
		envelope *cb.Envelope
		code     peer.TxValidationCode
		wantErr  string
	}{
		{
			name:     "matching valid transaction",
			txID:     "target-tx",
			envelope: envelope,
			code:     peer.TxValidationCode_VALID,
		},
		{
			name:     "invalid peer validation code",
			txID:     "target-tx",
			envelope: envelope,
			code:     peer.TxValidationCode_ENDORSEMENT_POLICY_FAILURE,
			wantErr:  "ENDORSEMENT_POLICY_FAILURE",
		},
		{
			name:     "different peer transaction",
			txID:     "target-tx",
			envelope: testEnvelope(t, "other-tx"),
			code:     peer.TxValidationCode_VALID,
			wantErr:  "does not match",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw, err := proto.Marshal(&peer.ProcessedTransaction{
				TransactionEnvelope: test.envelope,
				ValidationCode:      int32(test.code),
			})
			require.NoError(t, err)
			code, err := validateProcessedTransaction(raw, test.txID, envelope)
			if test.wantErr != "" {
				require.ErrorContains(t, err, test.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, peer.TxValidationCode_VALID, code)
		})
	}

	_, err := validateProcessedTransaction([]byte{0xff}, "target-tx", envelope)
	require.ErrorContains(t, err, "parse processed transaction")
}

func TestVerifyStateWriteRequiresExpectedKeyValue(t *testing.T) {
	kvRWSet := &kvrwset.KVRWSet{
		Writes: []*kvrwset.KVWrite{{Key: "pq3-asset", Value: []byte("updated-value")}},
	}
	transactionRWSet := &rwset.TxReadWriteSet{
		NsRwset: []*rwset.NsReadWriteSet{{
			Namespace: "pq3asset",
			Rwset:     protoutil.MarshalOrPanic(kvRWSet),
		}},
	}
	results := protoutil.MarshalOrPanic(transactionRWSet)

	require.NoError(t, verifyStateWrite(results, "pq3asset", "pq3-asset", "updated-value"))
	require.ErrorContains(t,
		verifyStateWrite(results, "pq3asset", "pq3-asset", "initial-value"),
		"does not write",
	)
	require.ErrorContains(t,
		verifyStateWrite(results, "another-chaincode", "pq3-asset", "updated-value"),
		"does not write",
	)
}

func TestRequiredProfileComesFromAuthenticatedChannel(t *testing.T) {
	tests := []struct {
		name        string
		local       string
		channelCaps map[string]*cb.Capability
		wantProfile string
		wantErr     string
	}{
		{
			name:        "temporary profile",
			local:       oqs.TemporaryHybridProfileV1,
			channelCaps: map[string]*cb.Capability{capabilities.PactwayHybridCertificateV1: {}},
			wantProfile: oqs.TemporaryHybridProfileV1,
		},
		{
			name:        "permanent profile",
			local:       oqs.PermanentHybridProfileV1,
			channelCaps: map[string]*cb.Capability{capabilities.PactwayHybridCertificatePactwayV1: {}},
			wantProfile: oqs.PermanentHybridProfileV1,
		},
		{
			name:  "local profile mismatch",
			local: oqs.TemporaryHybridProfileV1,
			channelCaps: map[string]*cb.Capability{
				capabilities.PactwayHybridCertificatePactwayV1: {},
			},
			wantErr: "does not match authenticated channel profile",
		},
		{
			name:  "both profiles in channel",
			local: oqs.TemporaryHybridProfileV1,
			channelCaps: map[string]*cb.Capability{
				capabilities.PactwayHybridCertificateV1:        {},
				capabilities.PactwayHybridCertificatePactwayV1: {},
			},
			wantErr: "does not require exactly one supported Pactway hybrid profile",
		},
		{
			name:        "channel without profile",
			local:       oqs.TemporaryHybridProfileV1,
			channelCaps: map[string]*cb.Capability{},
			wantErr:     "does not require exactly one supported Pactway hybrid profile",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("PACTWAY_HYBRID_PROFILE", test.local)
			t.Setenv("PACTWAY_ISOLATED_DEVELOPMENT", "true")
			profile, err := requiredProfileFromChannel(capabilities.NewChannelProvider(test.channelCaps))
			if test.wantErr != "" {
				require.ErrorContains(t, err, test.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.wantProfile, profile.Name())
		})
	}
}

func TestVerifySerializedIdentityProfileRequiresBothSelectedExtensions(t *testing.T) {
	profile, err := oqs.HybridCertificateProfileByName(
		oqs.PermanentHybridProfileV1,
		oqs.ProfileUseIsolatedDevelopment,
	)
	require.NoError(t, err)

	for _, test := range []struct {
		name       string
		extensions []pkix.Extension
		wantErr    string
	}{
		{
			name: "matching profile",
			extensions: []pkix.Extension{
				{Id: profile.ProfileKeyOID()},
				{Id: profile.PQSignatureOID()},
			},
		},
		{
			name: "missing PQ signature OID",
			extensions: []pkix.Extension{
				{Id: profile.ProfileKeyOID()},
			},
			wantErr: "missing profile extension OID",
		},
		{
			name: "temporary profile OIDs",
			extensions: []pkix.Extension{
				{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 32473, 1, 1}},
				{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 32473, 1, 2}},
			},
			wantErr: "missing profile extension OID",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			serialized := testSerializedIdentity(t, test.extensions)
			err := verifySerializedIdentityProfile(serialized, profile)
			if test.wantErr != "" {
				require.ErrorContains(t, err, test.wantErr)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestVerifyBlockSignerProfilesDoesNotRejectExpiredCertificate(t *testing.T) {
	profile, err := oqs.HybridCertificateProfileByName(
		oqs.PermanentHybridProfileV1,
		oqs.ProfileUseIsolatedDevelopment,
	)
	require.NoError(t, err)
	expiredAt := time.Now().Add(-time.Hour)
	creator := testSerializedIdentityWithValidity(t, []pkix.Extension{
		{Id: profile.ProfileKeyOID()},
		{Id: profile.PQSignatureOID()},
	}, expiredAt.Add(-time.Hour), expiredAt)
	signatureHeader := protoutil.MarshalOrPanic(&cb.SignatureHeader{Creator: creator})
	signatureMetadata := protoutil.MarshalOrPanic(&cb.Metadata{
		Signatures: []*cb.MetadataSignature{{SignatureHeader: signatureHeader}},
	})
	signatureIndex := int(cb.BlockMetadataIndex_SIGNATURES)
	metadata := make([][]byte, signatureIndex+1)
	metadata[signatureIndex] = signatureMetadata
	block := &cb.Block{Metadata: &cb.BlockMetadata{Metadata: metadata}}

	require.NoError(t, verifyBlockSignerProfiles(block, profile))
}

func testSerializedIdentity(t *testing.T, extensions []pkix.Extension) []byte {
	now := time.Now()
	return testSerializedIdentityWithValidity(t, extensions, now.Add(-time.Hour), now.Add(time.Hour))
}

func testSerializedIdentityWithValidity(
	t *testing.T,
	extensions []pkix.Extension,
	notBefore time.Time,
	notAfter time.Time,
) []byte {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		ExtraExtensions:       extensions,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	identity, err := proto.Marshal(&mspprotos.SerializedIdentity{Mspid: "Org1MSP", IdBytes: certificate})
	require.NoError(t, err)
	return identity
}

func testEnvelope(t *testing.T, txID string) *cb.Envelope {
	t.Helper()
	channelHeader := protoutil.MarshalOrPanic(&cb.ChannelHeader{TxId: txID})
	payload := protoutil.MarshalOrPanic(&cb.Payload{
		Header: &cb.Header{ChannelHeader: channelHeader},
	})
	return &cb.Envelope{Payload: payload}
}

func testBlock(envelope *cb.Envelope, validationFilter []byte) *cb.Block {
	rawEnvelope := protoutil.MarshalOrPanic(envelope)
	filterIndex := int(cb.BlockMetadataIndex_TRANSACTIONS_FILTER)
	metadata := make([][]byte, filterIndex+1)
	if validationFilter != nil {
		metadata[filterIndex] = validationFilter
	}
	return &cb.Block{
		Header:   &cb.BlockHeader{Number: 1},
		Data:     &cb.BlockData{Data: [][]byte{rawEnvelope}},
		Metadata: &cb.BlockMetadata{Metadata: metadata},
	}
}
