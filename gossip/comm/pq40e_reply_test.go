/*
SPDX-License-Identifier: Apache-2.0
*/

package comm

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/hyperledger/fabric-lib-go/common/flogging"
	"github.com/hyperledger/fabric-lib-go/common/metrics/disabled"
	proto "github.com/hyperledger/fabric-protos-go-apiv2/gossip"
	"github.com/hyperledger/fabric/gossip/metrics"
	"github.com/hyperledger/fabric/gossip/protoext"
	"github.com/stretchr/testify/require"
)

type pq40eReplyStream struct {
	send func(*proto.Envelope) error
}

func (s pq40eReplyStream) Send(envelope *proto.Envelope) error { return s.send(envelope) }
func (pq40eReplyStream) Recv() (*proto.Envelope, error)        { return nil, nil }
func (pq40eReplyStream) Context() context.Context              { return context.Background() }

func TestPQ40EMixedPrivateRepliesAcrossConnectionRestart(t *testing.T) {
	wire := make(chan *proto.Envelope, 2)
	newConn := func() *connection {
		c := newConnection(nil, nil, pq40eReplyStream{send: func(e *proto.Envelope) error {
			wire <- e
			return nil
		}}, metrics.NewGossipMetrics(&disabled.Provider{}).CommMetrics, ConnConfig{SendBuffSize: 2})
		c.logger = flogging.MustGetLogger("pq40e.gossip.reply")
		t.Cleanup(c.close)
		return c
	}
	makeReply := func(channel string) *protoext.SignedGossipMessage {
		msg, err := protoext.NoopSign(&proto.GossipMessage{
			Channel: []byte(channel),
			Content: &proto.GossipMessage_PrivateRes{PrivateRes: &proto.RemotePvtDataResponse{}},
		})
		require.NoError(t, err)
		return msg
	}
	nextChannel := func() string {
		select {
		case packet := <-wire:
			msg, err := protoext.EnvelopeToGossipMessage(packet)
			require.NoError(t, err)
			return string(msg.GetChannel())
		case <-time.After(5 * time.Second):
			t.Fatal("private-data response did not reach the writer")
			return ""
		}
	}

	c := newConn()
	generation, revoke := context.WithCancel(t.Context())
	defer revoke()
	protected := makeReply("protected")
	done := make(chan struct{})
	go func() { c.sendProtectedReply(protected, generation); close(done) }()
	require.Eventually(t, func() bool { return len(c.outBuff) == 1 }, 5*time.Second, 10*time.Millisecond)
	c.send(makeReply("baseline"), func(error) {}, blockingSend)
	revoke()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("queued protected response did not release")
	}
	go c.writeToStream()
	require.Equal(t, "baseline", nextChannel())
	require.Empty(t, wire)
	c.close()

	recovered := newConn()
	go recovered.writeToStream()
	recovered.sendProtectedReply(protected, t.Context())
	require.Equal(t, "protected", nextChannel())
}

func TestPQ40EPrivateReplyDrainsAnInFlightWrite(t *testing.T) {
	entered := make(chan struct{})
	finish := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(finish) })
	defer unblock()
	stream := pq40eReplyStream{send: func(*proto.Envelope) error {
		close(entered)
		<-finish
		return context.Canceled
	}}
	c := newConnection(nil, nil, stream, metrics.NewGossipMetrics(&disabled.Provider{}).CommMetrics, ConnConfig{SendBuffSize: 1})
	c.logger = flogging.MustGetLogger("pq40e.gossip.reply")
	defer c.close()
	generation, revoke := context.WithCancel(t.Context())
	defer revoke()
	msg, err := protoext.NoopSign(&proto.GossipMessage{})
	require.NoError(t, err)
	go c.writeToStream()
	done := make(chan struct{})
	go func() { c.sendProtectedReply(msg, generation); close(done) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("protected writer did not start")
	}
	revoke()
	select {
	case <-c.stopChan:
	case <-time.After(5 * time.Second):
		t.Fatal("generation closure did not abort the transport")
	}
	select {
	case <-done:
		t.Fatal("protected response released before the writer returned")
	default:
	}
	unblock()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("protected response did not drain")
	}
}
