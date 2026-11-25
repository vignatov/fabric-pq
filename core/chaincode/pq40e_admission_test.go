/*
SPDX-License-Identifier: Apache-2.0
*/

package chaincode

import (
	"context"
	"testing"
	"time"

	"github.com/hyperledger/fabric-lib-go/common/metrics/disabled"
	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	pb "github.com/hyperledger/fabric-protos-go-apiv2/peer"
	"github.com/hyperledger/fabric/core/chaincode/lifecycle"
	"github.com/hyperledger/fabric/core/chaincode/mock"
	"github.com/hyperledger/fabric/core/common/ccprovider"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation/testfixture"
	"github.com/hyperledger/fabric/protoutil"
	"github.com/stretchr/testify/require"
)

func TestPQ40EMixedChaincodeAdmissionAndRestart(t *testing.T) {
	const baseline = "baseline"
	fixture := testfixture.New(t)
	genesis := testfixture.Genesis(t)
	dir := t.TempDir()
	store, err := activation.OpenStore(dir, nil)
	require.NoError(t, err)
	fixture.Provision(t, store, testfixture.Config(t, genesis))
	restart := func() *activation.Channel {
		t.Helper()
		store, err := activation.OpenStore(dir, nil)
		require.NoError(t, err)
		channel := fixture.Channel(store, activation.Ledger{LatestConfig: func() (*cb.Block, error) { return genesis, nil }})
		require.NoError(t, channel.Recover(true))
		return &channel
	}
	newSupport := func(channel *activation.Channel) (*ChaincodeSupport, *Handler, <-chan *pb.ChaincodeMessage) {
		t.Helper()
		registry := NewHandlerRegistry(true)
		stream := &mock.ChaincodeStream{}
		h := &Handler{
			chaincodeID: "cc", state: Ready, chatStream: stream, TXContexts: NewTransactionContexts(),
			LedgerGetter: &mock.LedgerGetter{}, Metrics: NewHandlerMetrics(&disabled.Provider{}),
			RequiresProtection: func(id string) bool { return id == testfixture.ChannelID },
		}
		require.NoError(t, registry.Register(h))
		started := make(chan *pb.ChaincodeMessage, 1)
		stream.SendCalls(func(msg *pb.ChaincodeMessage) error {
			if msg.GetTxid() == "interrupted" {
				started <- msg
				return nil
			}
			h.Notify(&pb.ChaincodeMessage{Type: pb.ChaincodeMessage_COMPLETED, Txid: msg.GetTxid(), ChannelId: msg.GetChannelId()})
			return nil
		})
		definitions := &mock.Lifecycle{}
		definitions.ChaincodeEndorsementInfoReturns(&lifecycle.ChaincodeEndorsementInfo{ChaincodeID: "cc"}, nil)
		return &ChaincodeSupport{
			HandlerRegistry: registry, Lifecycle: definitions, ExecuteTimeout: 5 * time.Second,
			AcquireAdmission: func(id string) (context.Context, func(), bool) {
				if id != testfixture.ChannelID {
					return nil, nil, true
				}
				_, generation, release, admitted := channel.Gate.Acquire()
				return generation, release, admitted
			},
		}, h, started
	}
	invoke := func(cs *ChaincodeSupport, channel, txid string) error {
		_, err := cs.Invoke(&ccprovider.TransactionParams{ChannelID: channel, TxID: txid}, "cc", &pb.ChaincodeInput{})
		return err
	}
	channel := restart()
	cs, handler, started := newSupport(channel)
	require.NoError(t, invoke(cs, testfixture.ChannelID, "initial"))
	result := make(chan error, 1)
	go func() { result <- invoke(cs, testfixture.ChannelID, "interrupted") }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("chaincode did not receive the invocation")
	}
	_, generation, release, admitted := channel.Gate.Acquire()
	require.True(t, admitted)
	release()
	drained := make(chan struct{})
	go func() { channel.Suspend(); close(drained) }()
	select {
	case <-generation.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("protected chaincode generation did not close")
	}
	require.NoError(t, invoke(cs, baseline, "baseline-live"))
	require.ErrorContains(t, invoke(cs, testfixture.ChannelID, "rejected"), "admission is closed")
	select {
	case <-drained:
		t.Fatal("activation escaped an outstanding chaincode invocation")
	default:
	}
	handler.Notify(&pb.ChaincodeMessage{Type: pb.ChaincodeMessage_COMPLETED, Txid: "interrupted", ChannelId: testfixture.ChannelID})
	require.ErrorContains(t, <-result, "generation closed")
	<-drained
	cs, handler, _ = newSupport(restart())
	require.NoError(t, invoke(cs, testfixture.ChannelID, "recovered"))
	require.NoError(t, invoke(cs, baseline, "baseline-recovered"))
	_, err = handler.HandleInvokeChaincode(&pb.ChaincodeMessage{Payload: protoutil.MarshalOrPanic(&pb.ChaincodeSpec{
		ChaincodeId: &pb.ChaincodeID{Name: "cc/" + testfixture.ChannelID},
	})}, &TransactionContext{ChannelID: baseline})
	require.ErrorContains(t, err, "cross-channel invocation into a protected channel is disabled")
}
