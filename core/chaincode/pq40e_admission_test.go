/*
SPDX-License-Identifier: Apache-2.0
*/

package chaincode

import (
	"context"
	"io"
	"sync"
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
	restart := chaincodeAdmissionFixture(t)
	newSupport := func(channel *activation.Channel) (*ChaincodeSupport, *Handler, <-chan *pb.ChaincodeMessage) {
		t.Helper()
		registry := NewHandlerRegistry(true)
		stream := &mock.ChaincodeStream{}
		h := &Handler{
			chaincodeID: "cc", state: Ready, chatStream: stream, TXContexts: NewTransactionContexts(),
			LedgerGetter: &mock.LedgerGetter{}, Metrics: NewHandlerMetrics(&disabled.Provider{}),
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
	cs, _, _ = newSupport(restart())
	require.NoError(t, invoke(cs, testfixture.ChannelID, "recovered"))
	require.NoError(t, invoke(cs, baseline, "baseline-recovered"))
}

func TestPQ40ECrossChannelShimResponseRevocationAndRestart(t *testing.T) {
	const baseline = "baseline"
	const payload = "target ledger response"
	restart := chaincodeAdmissionFixture(t)
	channel := restart()

	newHandler := func(channel *activation.Channel, stream *abortableTestShim) (*Handler, *mock.PeerLedger, *mock.ACLProvider) {
		t.Helper()
		ledgerGetter := &mock.LedgerGetter{}
		ledger := &mock.PeerLedger{}
		ledger.NewTxSimulatorReturns(&mock.TxSimulator{}, nil)
		ledger.NewHistoryQueryExecutorReturns(&mock.HistoryQueryExecutor{}, nil)
		ledgerGetter.GetLedgerReturns(ledger)
		registry := NewHandlerRegistry(true)
		targetStream := &mock.ChaincodeStream{}
		target := &Handler{chaincodeID: "target", state: Ready, chatStream: targetStream, TXContexts: NewTransactionContexts(), LedgerGetter: ledgerGetter}
		require.NoError(t, registry.Register(target))
		targetStream.SendCalls(func(msg *pb.ChaincodeMessage) error {
			result := payload
			if msg.GetChannelId() == baseline {
				result = baseline
			}
			target.Notify(&pb.ChaincodeMessage{
				Type: pb.ChaincodeMessage_COMPLETED, Txid: msg.GetTxid(), ChannelId: msg.GetChannelId(), Payload: []byte(result),
			})
			return nil
		})
		definitions := &mock.Lifecycle{}
		definitions.ChaincodeEndorsementInfoReturns(&lifecycle.ChaincodeEndorsementInfo{ChaincodeID: "target"}, nil)
		support := &ChaincodeSupport{
			HandlerRegistry: registry, Lifecycle: definitions, ExecuteTimeout: 5 * time.Second,
			AcquireAdmission: func(id string) (context.Context, func(), bool) {
				if id != testfixture.ChannelID {
					return nil, nil, true
				}
				_, generation, release, admitted := channel.Gate.Acquire()
				return generation, release, admitted
			},
		}
		acl := &mock.ACLProvider{}
		h := &Handler{
			chaincodeID: "caller", state: Ready, chatStream: stream, errChan: make(chan error, 1),
			TXContexts: NewTransactionContexts(), ActiveTransactions: NewActiveTransactions(),
			ACLProvider: acl, LedgerGetter: ledgerGetter, Invoker: support, Metrics: NewHandlerMetrics(&disabled.Provider{}),
			acquireAdmission: support.admit,
		}
		return h, ledger, acl
	}
	request := func(h *Handler, txid, target string) *pb.ChaincodeMessage {
		t.Helper()
		_, err := h.TXContexts.Create(&ccprovider.TransactionParams{
			ChannelID: baseline, TxID: txid, TXSimulator: &mock.TxSimulator{}, SignedProp: &pb.SignedProposal{},
		})
		require.NoError(t, err)
		return &pb.ChaincodeMessage{
			Type: pb.ChaincodeMessage_INVOKE_CHAINCODE, ChannelId: baseline, Txid: txid,
			Payload: protoutil.MarshalOrPanic(&pb.ChaincodeSpec{
				ChaincodeId: &pb.ChaincodeID{Name: "callee/" + target}, Input: &pb.ChaincodeInput{},
			}),
		}
	}
	assertResponse := func(msg *pb.ChaincodeMessage, txid, result string) {
		t.Helper()
		require.Equal(t, txid, msg.GetTxid())
		require.Equal(t, baseline, msg.GetChannelId())
		require.Equal(t, pb.ChaincodeMessage_RESPONSE, msg.GetType())
		require.Contains(t, string(msg.GetPayload()), result)
	}
	assertRevoked := func(msg *pb.ChaincodeMessage, txid, reason string) {
		t.Helper()
		require.Equal(t, txid, msg.GetTxid())
		require.Equal(t, pb.ChaincodeMessage_ERROR, msg.GetType())
		require.Contains(t, string(msg.GetPayload()), reason)
		require.NotContains(t, string(msg.GetPayload()), payload)
	}
	newStream := func() (*abortableTestShim, chan *pb.ChaincodeMessage) {
		sent := make(chan *pb.ChaincodeMessage, 4)
		stream := &abortableTestShim{closed: make(chan struct{})}
		stream.SendCalls(func(msg *pb.ChaincodeMessage) error { sent <- msg; return nil })
		return stream, sent
	}

	stream, sent := newStream()
	h, ledger, acl := newHandler(channel, stream)
	require.NoError(t, h.handleMessage(request(h, "initial", testfixture.ChannelID)))
	assertResponse(awaitShim(t, sent), "initial", payload)

	// Occupy the send slot with an unrelated response. The queued protected
	// response should release its lease on revocation without aborting the shim.
	blocked, unblock := make(chan struct{}), make(chan struct{})
	finish := sync.OnceFunc(func() { close(unblock) })
	t.Cleanup(finish)
	stream.SendCalls(func(msg *pb.ChaincodeMessage) error {
		if msg.GetTxid() == "blocker" {
			close(blocked)
			<-unblock
			return nil
		}
		sent <- msg
		return nil
	})
	h.serialSendAsync(&pb.ChaincodeMessage{Txid: "blocker"})
	awaitShim(t, blocked)
	h.handleInvokeTransaction(request(h, "queued", testfixture.ChannelID))
	require.Equal(t, 2, ledger.NewTxSimulatorCallCount())
	drained := make(chan struct{})
	go func() { channel.Suspend(); close(drained) }()
	awaitShim(t, drained)
	select {
	case <-stream.closed:
		t.Fatal("revoking a queued response closed the source shim")
	default:
	}
	finish()
	assertRevoked(awaitShim(t, sent), "queued", errProtectedShimResponseRevoked.Error())
	h.handleInvokeTransaction(request(h, "closed", testfixture.ChannelID))
	assertRevoked(awaitShim(t, sent), "closed", "protected channel admission is closed")
	require.Equal(t, 2, acl.CheckACLCallCount())
	require.Equal(t, 2, ledger.NewTxSimulatorCallCount())
	require.NoError(t, h.handleMessage(request(h, "baseline", baseline)))
	assertResponse(awaitShim(t, sent), "baseline", baseline)

	// Recreate the signed checkpoint and shim, then revoke a response that
	// already entered Send. The drain waits until that write has unwound.
	channel = restart()
	stream, sent = newStream()
	h, _, _ = newHandler(channel, stream)
	started, done := make(chan struct{}), make(chan struct{})
	finish = sync.OnceFunc(func() { close(done) })
	t.Cleanup(finish)
	stream.SendCalls(func(msg *pb.ChaincodeMessage) error {
		if msg.GetTxid() != "writing" {
			sent <- msg
			return nil
		}
		close(started)
		<-done
		return io.ErrClosedPipe
	})
	require.NoError(t, h.handleMessage(request(h, "after-restart", testfixture.ChannelID)))
	assertResponse(awaitShim(t, sent), "after-restart", payload)
	require.NoError(t, h.handleMessage(request(h, "writing", testfixture.ChannelID)))
	awaitShim(t, started)
	drained = make(chan struct{})
	go func() { channel.Suspend(); close(drained) }()
	awaitShim(t, stream.closed)
	require.ErrorIs(t, awaitShim(t, h.errChan), errProtectedShimResponseRevoked)
	select {
	case <-drained:
		t.Fatal("channel drained before the source shim write returned")
	default:
	}
	finish()
	awaitShim(t, drained)

	stream, sent = newStream()
	h, _, _ = newHandler(restart(), stream)
	require.NoError(t, h.handleMessage(request(h, "fresh-stream", testfixture.ChannelID)))
	assertResponse(awaitShim(t, sent), "fresh-stream", payload)
}

type abortableTestShim struct {
	mock.ChaincodeStream
	closed chan struct{}
	once   sync.Once
}

func (s *abortableTestShim) Abort() { s.once.Do(func() { close(s.closed) }) }

func awaitShim[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for chaincode shim")
		var zero T
		return zero
	}
}

func chaincodeAdmissionFixture(t *testing.T) func() *activation.Channel {
	t.Helper()
	fixture := testfixture.New(t)
	genesis := testfixture.Genesis(t)
	dir := t.TempDir()
	store, err := activation.OpenStore(dir, nil)
	require.NoError(t, err)
	fixture.Provision(t, store, testfixture.Config(t, genesis))
	return func() *activation.Channel {
		t.Helper()
		store, err := activation.OpenStore(dir, nil)
		require.NoError(t, err)
		channel := fixture.Channel(store, activation.Ledger{
			LatestConfig: func() (*cb.Block, error) { return genesis, nil },
			Block:        func(uint64) (*cb.Block, error) { return genesis, nil },
		})
		require.NoError(t, channel.Recover(true))
		return &channel
	}
}
