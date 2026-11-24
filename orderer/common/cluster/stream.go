/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cluster

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hyperledger/fabric-lib-go/common/flogging"
	"github.com/hyperledger/fabric-protos-go-apiv2/orderer"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

// Stream is used to send/receive messages to/from the remote cluster member.
type Stream struct {
	abortChan    <-chan struct{}
	sendBuff     chan queuedStep
	queueMu      sync.Mutex
	queueClosed  bool
	commShutdown chan struct{}
	abortReason  *atomic.Value
	metrics      *Metrics
	ID           uint64
	Channel      string
	NodeName     string
	Endpoint     string
	Logger       *flogging.FabricLogger
	Timeout      time.Duration
	StepClient   StepClientStream
	Cancel       func(error)
	canceled     *uint32
	expCheck     *certificateExpirationCheck
}

type queuedStep struct {
	ctx     context.Context
	request *orderer.StepRequest
	report  func(error)
}

// StreamOperation denotes an operation done by a stream, such a Send or Receive.
type StreamOperation func() (*orderer.StepResponse, error)

// Canceled returns whether the stream was canceled.
func (stream *Stream) Canceled() bool {
	return atomic.LoadUint32(stream.canceled) == uint32(1)
}

// Send sends the given request to the remote cluster member.
func (stream *Stream) Send(request *orderer.StepRequest) error {
	return stream.SendWithReport(request, func(_ error) {})
}

// SendWithReport sends the given request to the remote cluster member and invokes report on the send result.
func (stream *Stream) SendWithReport(request *orderer.StepRequest, report func(error)) error {
	return stream.SendWithReportContext(context.Background(), request, report)
}

// SendWithReportContext allows a blocked enqueue to be canceled, checks queued
// work before sending, and cancels the stream if an in-flight send is canceled.
// The completion report follows termination of that send. Callers must still
// retain their admission lease until the report; enqueue alone is not enough.
func (stream *Stream) SendWithReportContext(ctx context.Context, request *orderer.StepRequest, report func(error)) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if stream.Canceled() {
		return errors.New(stream.abortReason.Load().(string))
	}
	var allowDrop bool
	// We want to drop consensus transactions if the remote node cannot keep up with us,
	// otherwise we'll slow down the entire FSM.
	if request.GetConsensusRequest() != nil {
		allowDrop = true
	}

	return stream.sendOrDrop(ctx, request, allowDrop, report)
}

// SendWithGeneration holds the channel's serving generation until an accepted
// request has been sent or discarded. Closing the generation aborts the
// channel-scoped stream, including any in-flight send, before releasing the
// lease. Completion callbacks are notifications and must not use the lease.
func (stream *Stream) SendWithGeneration(ctx context.Context, gate *activation.Gate, expected context.Context, request *orderer.StepRequest, report func(error)) error {
	if gate == nil {
		return errors.New("protected channel generation is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	_, generation, release, ok := gate.AcquireMatching(expected)
	if !ok {
		return errors.New("protected channel admission is closed")
	}
	sendContext, cancel := context.WithCancel(generation)
	stopRequest := context.AfterFunc(ctx, cancel)
	abortFinished := make(chan struct{})
	stopAbort := context.AfterFunc(generation, func() {
		defer close(abortFinished)
		stream.Cancel(context.Canceled)
	})
	complete := sync.OnceFunc(func() {
		stopRequest()
		cancel()
		if !stopAbort() {
			<-abortFinished
		}
		release()
	})
	err := stream.SendWithReportContext(sendContext, request, func(err error) {
		complete()
		report(err)
	})
	if err != nil {
		complete()
	}
	return err
}

// sendOrDrop sends the given request to the remote cluster member, or drops it
// if it is a consensus request and the queue is full.
func (stream *Stream) sendOrDrop(ctx context.Context, request *orderer.StepRequest, allowDrop bool, report func(error)) error {
	stream.queueMu.Lock()
	defer stream.queueMu.Unlock()
	if stream.queueClosed {
		return errors.New("cluster stream is closed")
	}
	msgType := "transaction"
	if allowDrop {
		msgType = "consensus"
	}

	stream.metrics.reportQueueOccupancy(stream.Endpoint, msgType, stream.Channel, len(stream.sendBuff), cap(stream.sendBuff))

	if allowDrop && len(stream.sendBuff) == cap(stream.sendBuff) {
		stream.Cancel(errOverflow)
		stream.metrics.reportMessagesDropped(stream.Endpoint, stream.Channel)
		return errOverflow
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-stream.abortChan:
		return errors.Errorf("stream %d aborted", stream.ID)
	case stream.sendBuff <- queuedStep{ctx: ctx, request: request, report: report}:
		return nil
	case <-stream.commShutdown:
		return errors.New("cluster communication is shut down")
	}
}

// sendMessage sends the request down the stream
func (stream *Stream) sendMessage(ctx context.Context, request *orderer.StepRequest, report func(error)) {
	start := time.Now()
	var err error
	defer func() {
		message := fmt.Sprintf("Send of %s to %s(%s) took %v",
			requestAsString(request), stream.NodeName, stream.Endpoint, time.Since(start))
		if err != nil {
			stream.Logger.Warnf("%s but failed due to %s", message, err.Error())
		} else {
			stream.Logger.Debug(message)
		}
	}()

	f := func() (*orderer.StepResponse, error) {
		startSend := time.Now()
		stream.expCheck.checkExpiration(startSend, stream.Channel)
		err := stream.StepClient.Send(request)
		stream.metrics.reportMsgSendTime(stream.Endpoint, stream.Channel, time.Since(startSend))
		return nil, err
	}

	_, err = stream.operateWithTimeoutContext(ctx, f, report)
}

func (stream *Stream) serviceStream() {
	streamStartTime := time.Now()
	defer func() {
		stream.Cancel(errAborted)
		stream.failQueued(errAborted)
		stream.Logger.Debugf("Stream %d to (%s) terminated with total lifetime of %s",
			stream.ID, stream.Endpoint, time.Since(streamStartTime))
	}()

	for {
		select {
		case reqReport := <-stream.sendBuff:
			if err := reqReport.ctx.Err(); err != nil {
				reqReport.report(err)
				continue
			}
			stream.sendMessage(reqReport.ctx, reqReport.request, reqReport.report)
			if stream.Canceled() {
				return
			}
		case <-stream.abortChan:
			return
		case <-stream.commShutdown:
			return
		}
	}
}

// failQueued serializes shutdown with enqueue and reports every accepted item
// that the worker did not process. Callbacks run outside the queue lock.
func (stream *Stream) failQueued(cause error) {
	stream.queueMu.Lock()
	stream.queueClosed = true
	var pending []queuedStep
	for {
		select {
		case entry := <-stream.sendBuff:
			pending = append(pending, entry)
		default:
			stream.queueMu.Unlock()
			for _, entry := range pending {
				entry.report(cause)
			}
			return
		}
	}
}

// Recv receives a message from a remote cluster member.
func (stream *Stream) Recv() (*orderer.StepResponse, error) {
	start := time.Now()
	defer func() {
		if !stream.Logger.IsEnabledFor(zap.DebugLevel) {
			return
		}
		stream.Logger.Debugf("Receive from %s(%s) took %v", stream.NodeName, stream.Endpoint, time.Since(start))
	}()

	f := func() (*orderer.StepResponse, error) {
		return stream.StepClient.Recv()
	}

	return stream.operateWithTimeout(f, func(_ error) {})
}

// operateWithTimeout performs the given operation on the stream, and blocks until the timeout expires.
func (stream *Stream) operateWithTimeout(invoke StreamOperation, report func(error)) (*orderer.StepResponse, error) {
	return stream.operateWithTimeoutContext(context.Background(), invoke, report)
}

func (stream *Stream) operateWithTimeoutContext(ctx context.Context, invoke StreamOperation, report func(error)) (*orderer.StepResponse, error) {
	if err := ctx.Err(); err != nil {
		report(err)
		return nil, err
	}
	timer := time.NewTimer(stream.Timeout)
	defer timer.Stop()

	var operationEnded sync.WaitGroup
	operationEnded.Add(1)

	responseChan := make(chan struct {
		res *orderer.StepResponse
		err error
	}, 1)

	go func() {
		defer operationEnded.Done()
		res, err := invoke()
		responseChan <- struct {
			res *orderer.StepResponse
			err error
		}{res: res, err: err}
	}()

	select {
	case r := <-responseChan:
		if err := ctx.Err(); err != nil {
			stream.Cancel(err)
			report(err)
			return nil, err
		}
		report(r.err)
		if r.err != nil {
			stream.Cancel(r.err)
		}
		return r.res, r.err
	case <-timer.C:
		stream.Logger.Warningf("Stream %d to %s(%s) was forcibly terminated because timeout (%v) expired",
			stream.ID, stream.NodeName, stream.Endpoint, stream.Timeout)
		stream.Cancel(errTimeout)
		// Wait for the operation goroutine to end
		operationEnded.Wait()
		report(errTimeout)
		return nil, errTimeout
	case <-ctx.Done():
		err := ctx.Err()
		stream.Cancel(err)
		operationEnded.Wait()
		report(err)
		return nil, err
	}
}
