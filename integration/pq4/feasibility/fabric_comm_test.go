/*
SPDX-License-Identifier: Apache-2.0
*/

package feasibility

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/hyperledger/fabric/internal/pkg/comm"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/peer"
)

func pemPair(t *testing.T, cert tls.Certificate) ([]byte, []byte) {
	t.Helper()
	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func TestFabricCommMLDSACompatibility(t *testing.T) {
	ca := newAuthority(t)
	serverCert := ca.leaf(t, x509.ExtKeyUsageServerAuth, false)
	clientCert := ca.leaf(t, x509.ExtKeyUsageClientAuth, false)
	serverPEM, serverKey := pemPair(t, serverCert)
	clientPEM, clientKey := pemPair(t, clientCert)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})

	serverStates := make(chan tls.ConnectionState, 1)
	server, err := comm.NewGRPCServer("127.0.0.1:0", comm.ServerConfig{
		HealthCheckEnabled: true,
		SecOpts: comm.SecureOptions{
			UseTLS:            true,
			RequireClientCert: true,
			Certificate:       serverPEM,
			Key:               serverKey,
			ClientRootCAs:     [][]byte{caPEM},
		},
		UnaryInterceptors: []grpc.UnaryServerInterceptor{
			func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
				p, ok := peer.FromContext(ctx)
				if !ok {
					return nil, errors.New("missing server peer")
				}
				auth, ok := p.AuthInfo.(credentials.TLSInfo)
				if !ok {
					return nil, errors.New("missing server TLS state")
				}
				serverStates <- auth.State
				return handler(ctx, req)
			},
		},
	})
	require.NoError(t, err)
	serveErrors := make(chan error, 1)
	go func() { serveErrors <- server.Start() }()
	defer func() {
		server.Stop()
		require.NoError(t, <-serveErrors)
	}()

	clientConfig := comm.ClientConfig{
		KaOpts:      comm.DefaultKeepaliveOptions,
		DialTimeout: 5 * time.Second,
		SecOpts: comm.SecureOptions{
			UseTLS:             true,
			RequireClientCert:  true,
			Certificate:        clientPEM,
			Key:                clientKey,
			ServerRootCAs:      [][]byte{caPEM},
			ServerNameOverride: "pq4.example",
		},
	}
	options, err := clientConfig.DialOptions()
	require.NoError(t, err)

	_, classicalClient := configs(ca, serverCert, clientCert, true)
	classicalClient.CurvePreferences = []tls.CurveID{tls.X25519}
	for _, test := range []struct {
		name    string
		options []grpc.DialOption
		group   tls.CurveID
	}{
		{"Fabric client defaults", options, tls.X25519MLKEM768},
		{"classical-only client is accepted by baseline server", []grpc.DialOption{
			grpc.WithBlock(), grpc.WithTransportCredentials(credentials.NewTLS(classicalClient)),
		}, tls.X25519},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := grpc.DialContext(ctx, server.Address(), test.options...)
			require.NoError(t, err)
			defer conn.Close()
			var remote peer.Peer
			reply, err := healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{}, grpc.Peer(&remote))
			require.NoError(t, err)
			require.Equal(t, healthpb.HealthCheckResponse_SERVING, reply.Status)
			auth, ok := remote.AuthInfo.(credentials.TLSInfo)
			require.True(t, ok)
			serverState := <-serverStates
			require.Equal(t, uint16(tls.VersionTLS13), auth.State.Version)
			require.Equal(t, test.group, auth.State.CurveID)
			require.Equal(t, test.group, serverState.CurveID)
			require.NotEmpty(t, auth.State.VerifiedChains)
			require.NotEmpty(t, serverState.VerifiedChains)
			require.Equal(t, x509.MLDSA65, auth.State.PeerCertificates[0].SignatureAlgorithm)
			require.Equal(t, x509.MLDSA65, serverState.PeerCertificates[0].SignatureAlgorithm)
			require.False(t, auth.State.DidResume)
			t.Logf("Fabric comm mutual TLS actual group: %s", test.group)
		})
	}
}
