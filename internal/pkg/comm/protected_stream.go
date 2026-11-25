/*
SPDX-License-Identifier: Apache-2.0
*/

package comm

import (
	"context"
	"net"
	"sync"

	"google.golang.org/grpc/peer"
)

type revocableListener struct{ net.Listener }

type revocableAddr struct {
	net.Addr
	abort func()
}

type revocableConn struct {
	net.Conn
	remote *revocableAddr
}

func (l revocableListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	remote := &revocableAddr{Addr: conn.RemoteAddr(), abort: sync.OnceFunc(func() {
		// Drop pending writes and interrupt blocked gRPC sends on this
		// authenticated connection when its serving generation is revoked.
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.SetLinger(0)
		}
		_ = conn.Close()
	})}
	return &revocableConn{Conn: conn, remote: remote}, nil
}

func (c *revocableConn) RemoteAddr() net.Addr { return c.remote }

// RetainProtectedStream transfers a lease to a streaming gRPC call on a
// strict listener. Revocation aborts the underlying transport, including any
// writes blocked by HTTP/2 flow control. Multiplexed calls on that connection
// must reconnect. If this returns false, the caller still owns the lease.
func RetainProtectedStream(ctx, generation context.Context, release func()) bool {
	p, ok := peer.FromContext(ctx)
	if !ok || generation == nil || release == nil {
		return false
	}
	address, ok := p.Addr.(*revocableAddr)
	if !ok {
		return false
	}
	aborted := make(chan struct{})
	stop := context.AfterFunc(generation, func() {
		defer close(aborted)
		address.abort()
	})
	if retainUntilRPCEnd(ctx, false, func() {
		if !stop() {
			<-aborted
		}
		release()
	}) {
		return true
	}
	stop()
	return false
}
