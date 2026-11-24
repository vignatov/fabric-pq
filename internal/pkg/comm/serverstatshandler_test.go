/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package comm_test

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/hyperledger/fabric-lib-go/common/metrics"
	"github.com/hyperledger/fabric-lib-go/common/metrics/disabled"
	"github.com/hyperledger/fabric-lib-go/common/metrics/metricsfakes"
	"github.com/hyperledger/fabric/internal/pkg/comm"
	"github.com/hyperledger/fabric/internal/pkg/comm/testpb"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/stats"
	"google.golang.org/protobuf/proto"
)

func TestConnectionCounters(t *testing.T) {
	t.Parallel()
	gt := NewGomegaWithT(t)

	openConn := &metricsfakes.Counter{}
	closedConn := &metricsfakes.Counter{}
	sh := &comm.ServerStatsHandler{
		OpenConnCounter:   openConn,
		ClosedConnCounter: closedConn,
	}

	for i := 1; i <= 10; i++ {
		sh.HandleConn(context.Background(), &stats.ConnBegin{})
		gt.Expect(openConn.AddCallCount()).To(Equal(i))
	}

	for i := 1; i <= 5; i++ {
		sh.HandleConn(context.Background(), &stats.ConnEnd{})
		gt.Expect(closedConn.AddCallCount()).To(Equal(i))
	}
}

type responseLeaseServer struct {
	testpb.UnimplementedEmptyServiceServer
	acquired chan struct{}
	finish   chan struct{}
	released chan struct{}
}

func (s *responseLeaseServer) EmptyCall(ctx context.Context, _ *testpb.Empty) (*testpb.Empty, error) {
	if !comm.RetainUntilRPCEnd(ctx, func() { close(s.released) }) {
		return nil, context.Canceled
	}
	close(s.acquired)
	<-s.finish
	return &testpb.Empty{}, nil
}

func TestPQ40EResponseLeaseEndsWithGRPC(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv, err := comm.NewGRPCServerFromListener(listener, comm.ServerConfig{
		ServerStatsHandler: comm.NewServerStatsHandler(&disabled.Provider{}),
	})
	require.NoError(t, err)
	service := &responseLeaseServer{acquired: make(chan struct{}), finish: make(chan struct{}), released: make(chan struct{})}
	testpb.RegisterEmptyServiceServer(srv.Server(), service)
	go srv.Start()
	t.Cleanup(srv.Stop)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(ctx, listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	done := make(chan error, 1)
	go func() { _, err := testpb.NewEmptyServiceClient(conn).EmptyCall(ctx, &testpb.Empty{}); done <- err }()
	select {
	case <-service.acquired:
	case <-ctx.Done():
		t.Fatal("RPC did not acquire the response lease")
	}
	select {
	case <-service.released:
		t.Fatal("response lease released while handler was active")
	default:
	}
	close(service.finish)
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-ctx.Done():
		t.Fatal("RPC did not complete")
	}
	select {
	case <-service.released:
	case <-ctx.Done():
		t.Fatal("response lease was not released")
	}
}

func TestPQ40EResponseLeaseScopeEndsOnce(t *testing.T) {
	handler := &comm.ServerStatsHandler{}
	ctx := handler.TagRPC(context.Background(), &stats.RPCTagInfo{})
	count := 0
	require.True(t, comm.RetainUntilRPCEnd(ctx, func() { count++ }))
	require.True(t, comm.RetainUntilRPCEnd(ctx, func() { count++ }))
	handler.HandleRPC(ctx, &stats.OutPayload{})
	require.Zero(t, count)
	handler.HandleRPC(ctx, &stats.End{})
	handler.HandleRPC(ctx, &stats.End{})
	require.Equal(t, 2, count)
	require.False(t, comm.RetainUntilRPCEnd(ctx, func() { count++ }))
	require.False(t, comm.RetainUntilRPCEnd(context.Background(), func() {}))
}

type blockingResponseCodec struct {
	started chan struct{}
	finish  chan struct{}
}

func (c *blockingResponseCodec) Name() string { return "proto" }

func (c *blockingResponseCodec) Marshal(v any) ([]byte, error) {
	close(c.started)
	<-c.finish
	return proto.Marshal(v.(proto.Message))
}

func (c *blockingResponseCodec) Unmarshal(data []byte, v any) error {
	return proto.Unmarshal(data, v.(proto.Message))
}

func TestPQ40EResponseLeaseSurvivesBlockedSend(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	codec := &blockingResponseCodec{started: make(chan struct{}), finish: make(chan struct{})}
	server := grpc.NewServer(grpc.StatsHandler(comm.NewServerStatsHandler(&disabled.Provider{})), grpc.ForceServerCodec(codec))
	service := &responseLeaseServer{acquired: make(chan struct{}), finish: make(chan struct{}), released: make(chan struct{})}
	testpb.RegisterEmptyServiceServer(server, service)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	var finishService, finishCodec sync.Once
	t.Cleanup(func() {
		finishService.Do(func() { close(service.finish) })
		finishCodec.Do(func() { close(codec.finish) })
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(ctx, listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	done := make(chan error, 1)
	go func() { _, err := testpb.NewEmptyServiceClient(conn).EmptyCall(ctx, &testpb.Empty{}); done <- err }()
	select {
	case <-service.acquired:
	case <-ctx.Done():
		t.Fatal("RPC did not acquire the lease")
	}
	finishService.Do(func() { close(service.finish) })
	select {
	case <-codec.started:
	case <-ctx.Done():
		t.Fatal("response did not enter serialization")
	}
	select {
	case <-service.released:
		t.Fatal("lease released while response send was blocked")
	default:
	}
	finishCodec.Do(func() { close(codec.finish) })
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-ctx.Done():
		t.Fatal("RPC did not finish")
	}
	select {
	case <-service.released:
	case <-ctx.Done():
		t.Fatal("lease did not release after RPC completion")
	}
}

func TestConnMetricsGRPCServer(t *testing.T) {
	t.Parallel()
	gt := NewGomegaWithT(t)

	openConn := &metricsfakes.Counter{}
	closedConn := &metricsfakes.Counter{}
	fakeProvider := &metricsfakes.Provider{}
	fakeProvider.NewCounterStub = func(o metrics.CounterOpts) metrics.Counter {
		switch o.Name {
		case "conn_opened":
			return openConn
		case "conn_closed":
			return closedConn
		default:
			panic("unknown counter")
		}
	}

	listener, err := net.Listen("tcp", "localhost:0")
	gt.Expect(err).NotTo(HaveOccurred())
	srv, err := comm.NewGRPCServerFromListener(
		listener,
		comm.ServerConfig{
			SecOpts:            comm.SecureOptions{UseTLS: false},
			ServerStatsHandler: comm.NewServerStatsHandler(fakeProvider),
		},
	)
	gt.Expect(err).NotTo(HaveOccurred())

	// register the GRPC test server
	testpb.RegisterEmptyServiceServer(srv.Server(), &emptyServiceServer{})

	// start the server
	go srv.Start()
	defer srv.Stop()

	// test grpc connection counts
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	gt.Expect(openConn.AddCallCount()).To(Equal(0))
	gt.Expect(closedConn.AddCallCount()).To(Equal(0))

	// create GRPC client conn
	var clientConns []*grpc.ClientConn
	for i := 1; i <= 3; i++ {
		clientConn, err := grpc.DialContext(ctx, listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
		gt.Expect(err).NotTo(HaveOccurred())
		clientConns = append(clientConns, clientConn)

		// invoke service
		client := testpb.NewEmptyServiceClient(clientConn)
		_, err = client.EmptyCall(context.Background(), &testpb.Empty{})
		gt.Expect(err).NotTo(HaveOccurred())
		gt.Expect(openConn.AddCallCount()).To(Equal(i))
	}

	for i, conn := range clientConns {
		gt.Expect(closedConn.AddCallCount()).Should(Equal(i))
		conn.Close()
		gt.Eventually(closedConn.AddCallCount, time.Second).Should(Equal(i + 1))
	}
}
