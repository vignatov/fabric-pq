/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"testing"

	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-protos-go-apiv2/ledger/rwset"
	"github.com/hyperledger/fabric-protos-go-apiv2/ledger/rwset/kvrwset"
	peer "github.com/hyperledger/fabric-protos-go-apiv2/peer"
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
