/*
SPDX-License-Identifier: Apache-2.0
*/

package feasibility

import (
	"context"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"testing"
	"time"

	"github.com/hyperledger/fabric-lib-go/common/flogging/floggingtest"
	"github.com/hyperledger/fabric/internal/pkg/comm"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/peer"
)

func authenticatedCommPolicy(t *testing.T) *pqtransport.Policy {
	t.Helper()
	signer, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	public, ok := signer.Public().(*mldsa.PublicKey)
	require.True(t, ok)
	payload, err := json.Marshal(pqtransport.Document{
		Network: "network-a",
		Node:    "node-a",
		Version: 1,
		Profile: pqtransport.ProfileV1,
	})
	require.NoError(t, err)
	signature, err := signer.Sign(rand.Reader, payload, nil)
	require.NoError(t, err)
	checkpoint := &pqtransport.Checkpoint{Version: 1, Digest: sha256.Sum256(payload)}
	policy, err := pqtransport.Authenticate(payload, signature, public, checkpoint, "network-a", "node-a")
	require.NoError(t, err)
	return policy
}

func TestAuthenticatedPolicyFabricComm(t *testing.T) {
	policy := authenticatedCommPolicy(t)
	ca := newAuthority(t)
	serverCert := ca.leaf(t, x509.ExtKeyUsageServerAuth, false)
	clientCert := ca.leaf(t, x509.ExtKeyUsageClientAuth, false)
	serverPEM, serverKey := pemPair(t, serverCert)
	clientPEM, clientKey := pemPair(t, clientCert)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})

	for _, requireClient := range []bool{false, true} {
		name := "server authentication"
		if requireClient {
			name = "mutual authentication"
		}
		t.Run(name, func(t *testing.T) {
			logger, logs := floggingtest.NewTestLogger(t)
			serverStates := make(chan tls.ConnectionState, 1)
			server, err := comm.NewGRPCServer("127.0.0.1:0", comm.ServerConfig{
				Logger:             logger,
				HealthCheckEnabled: true,
				SecOpts: comm.SecureOptions{
					UseTLS:            true,
					RequireClientCert: requireClient,
					Certificate:       serverPEM,
					Key:               serverKey,
					ClientRootCAs:     [][]byte{caPEM},
					TransportPolicy:   policy,
				},
				UnaryInterceptors: []grpc.UnaryServerInterceptor{
					func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
						p, ok := peer.FromContext(ctx)
						if ok {
							if auth, ok := p.AuthInfo.(credentials.TLSInfo); ok {
								serverStates <- auth.State
							}
						}
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

			secure := comm.SecureOptions{
				UseTLS:             true,
				RequireClientCert:  requireClient,
				Certificate:        clientPEM,
				Key:                clientKey,
				ServerRootCAs:      [][]byte{caPEM},
				ServerNameOverride: "pq4.example",
				TransportPolicy:    policy,
			}
			client := comm.ClientConfig{SecOpts: secure, KaOpts: comm.DefaultKeepaliveOptions}
			options, err := client.Clone().DialOptions()
			require.NoError(t, err)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := grpc.DialContext(ctx, server.Address(), options...)
			require.NoError(t, err)
			defer conn.Close()
			var remote peer.Peer
			_, err = healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{}, grpc.Peer(&remote))
			require.NoError(t, err)
			clientState := remote.AuthInfo.(credentials.TLSInfo).State
			serverState := <-serverStates
			require.Equal(t, uint16(tls.VersionTLS13), clientState.Version)
			require.Equal(t, tls.X25519MLKEM768, clientState.CurveID)
			require.Equal(t, tls.X25519MLKEM768, serverState.CurveID)
			require.NotEmpty(t, clientState.VerifiedChains)
			require.NoError(t, pqtransport.CheckIdentity(clientState.VerifiedChains[0][0]))
			require.False(t, clientState.DidResume)
			if requireClient {
				require.NotEmpty(t, serverState.VerifiedChains)
				require.NoError(t, pqtransport.CheckIdentity(serverState.VerifiedChains[0][0]))
			} else {
				require.Empty(t, serverState.PeerCertificates)
				require.Empty(t, serverState.VerifiedChains)
			}
			t.Logf("Fabric comm: TLS 1.3, %s, verified ML-DSA-65 server, mutual=%t", clientState.CurveID, requireClient)

			_, baseClient := configs(ca, serverCert, clientCert, requireClient)
			baseClient.NextProtos = []string{"h2"}
			for _, test := range []struct {
				name  string
				edit  func(*tls.Config)
				cause string
			}{
				{"TLS 1.2", func(c *tls.Config) { c.MinVersion, c.MaxVersion = tls.VersionTLS12, tls.VersionTLS12 }, "unsupported versions"},
				{"classical-only key exchange", func(c *tls.Config) { c.CurvePreferences = []tls.CurveID{tls.X25519} }, "key exchange"},
			} {
				t.Run(test.name, func(t *testing.T) {
					logs.Reset()
					weak := baseClient.Clone()
					test.edit(weak)
					probe, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", server.Address(), weak)
					if err == nil {
						_ = probe.SetReadDeadline(time.Now().Add(3 * time.Second))
						_, err = probe.Read(make([]byte, 1))
						_ = probe.Close()
					}
					require.Error(t, err)
					require.Eventually(t, func() bool {
						return len(logs.MessagesContaining(test.cause)) > 0
					}, 3*time.Second, 10*time.Millisecond, "server did not report expected cause %q: %v", test.cause, logs.Messages())
				})
			}
			if requireClient {
				for _, test := range []struct {
					name  string
					certs []tls.Certificate
					cause string
				}{
					{"classical client identity", []tls.Certificate{ca.classicalLeaf(t, x509.ExtKeyUsageClientAuth)}, "client certificate: TLS endpoint identity is not ML-DSA-65"},
					{"missing client identity", nil, "client didn't provide a certificate"},
				} {
					t.Run(test.name, func(t *testing.T) {
						logs.Reset()
						weak := baseClient.Clone()
						weak.Certificates = test.certs
						probe, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", server.Address(), weak)
						if err == nil {
							_ = probe.SetReadDeadline(time.Now().Add(3 * time.Second))
							_, err = probe.Read(make([]byte, 1))
							_ = probe.Close()
						}
						require.Error(t, err)
						require.Eventually(t, func() bool {
							return len(logs.MessagesContaining(test.cause)) > 0
						}, 3*time.Second, 10*time.Millisecond, "server did not report expected cause %q: %v", test.cause, logs.Messages())
					})
				}
			}
			t.Run("replacement certificate cannot weaken server identity", func(t *testing.T) {
				logs.Reset()
				server.SetServerCertificate(ca.classicalLeaf(t, x509.ExtKeyUsageServerAuth))
				defer server.SetServerCertificate(serverCert)
				probe, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", server.Address(), baseClient)
				if err == nil {
					_ = probe.Close()
				}
				require.Error(t, err)
				require.Eventually(t, func() bool {
					return len(logs.MessagesContaining("server certificate: TLS endpoint identity is not ML-DSA-65")) > 0
				}, 3*time.Second, 10*time.Millisecond, "server did not report rejected replacement certificate: %v", logs.Messages())
			})
		})
	}
}

func TestStrictCommListenerRestart(t *testing.T) {
	policy := authenticatedCommPolicy(t)
	ca := newAuthority(t)
	serverCert := ca.leaf(t, x509.ExtKeyUsageServerAuth, false)
	clientCert := ca.leaf(t, x509.ExtKeyUsageClientAuth, false)
	serverPEM, serverKey := pemPair(t, serverCert)
	logger, logs := floggingtest.NewTestLogger(t)
	config := comm.ServerConfig{
		Logger: logger,
		SecOpts: comm.SecureOptions{
			UseTLS: true, Certificate: serverPEM, Key: serverKey, TransportPolicy: policy,
		},
	}
	_, baseClient := configs(ca, serverCert, clientCert, false)
	baseClient.NextProtos = []string{"h2"}
	address := "127.0.0.1:0"

	for attempt := 0; attempt < 2; attempt++ {
		server, err := comm.NewGRPCServer(address, config)
		require.NoError(t, err)
		address = server.Address()
		serveErrors := make(chan error, 1)
		go func() { serveErrors <- server.Start() }()
		t.Cleanup(func() { server.Stop() })

		approved := baseClient.Clone()
		approved.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768}
		probe, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", address, approved)
		require.NoError(t, err)
		state := probe.ConnectionState()
		require.Equal(t, uint16(tls.VersionTLS13), state.Version)
		require.Equal(t, tls.X25519MLKEM768, state.CurveID)
		require.NotEmpty(t, state.VerifiedChains)
		require.NoError(t, pqtransport.CheckIdentity(state.VerifiedChains[0][0]))
		require.NoError(t, probe.Close())

		logs.Reset()
		weak := baseClient.Clone()
		weak.CurvePreferences = []tls.CurveID{tls.X25519}
		probe, err = tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", address, weak)
		if err == nil {
			_ = probe.Close()
		}
		require.Error(t, err)
		require.Eventually(t, func() bool {
			return len(logs.MessagesContaining("key exchange")) > 0
		}, 3*time.Second, 10*time.Millisecond, "server did not report rejected key exchange on attempt %d: %v", attempt, logs.Messages())
		server.Stop()
		require.NoError(t, <-serveErrors)
	}
}

func TestStrictCommClientVerifiesServer(t *testing.T) {
	policy := authenticatedCommPolicy(t)
	ca := newAuthority(t)
	serverCert := ca.leaf(t, x509.ExtKeyUsageServerAuth, false)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})

	for _, test := range []struct {
		name       string
		serverCert tls.Certificate
		serverName string
		root       []byte
		cause      string
	}{
		{"classical server identity", ca.classicalLeaf(t, x509.ExtKeyUsageServerAuth), "pq4.example", caPEM, "server certificate: TLS endpoint identity is not ML-DSA-65"},
		{"wrong hostname", serverCert, "wrong.example", caPEM, "not wrong.example"},
		{"untrusted authority", serverCert, "pq4.example", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: newAuthority(t).cert.Raw}), "unknown authority"},
	} {
		t.Run(test.name, func(t *testing.T) {
			serverPEM, serverKey := pemPair(t, test.serverCert)
			server, err := comm.NewGRPCServer("127.0.0.1:0", comm.ServerConfig{
				SecOpts: comm.SecureOptions{UseTLS: true, Certificate: serverPEM, Key: serverKey},
			})
			require.NoError(t, err)
			serveErrors := make(chan error, 1)
			go func() { serveErrors <- server.Start() }()
			defer func() {
				server.Stop()
				require.NoError(t, <-serveErrors)
			}()
			secure := comm.SecureOptions{
				UseTLS:             true,
				ServerRootCAs:      [][]byte{test.root},
				ServerNameOverride: test.serverName,
				TransportPolicy:    policy,
			}
			config, err := secure.TLSConfig()
			require.NoError(t, err)
			config.NextProtos = []string{"h2"}
			probe, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", server.Address(), config)
			if err == nil {
				_ = probe.Close()
			}
			require.ErrorContains(t, err, test.cause)
		})
	}

	t.Run("no plaintext or missing policy", func(t *testing.T) {
		_, err := (comm.SecureOptions{TransportPolicy: policy}).TLSConfig()
		require.ErrorContains(t, err, "requires TLS")
		_, err = (comm.SecureOptions{UseTLS: true, TransportPolicy: &pqtransport.Policy{}}).TLSConfig()
		require.ErrorContains(t, err, "authenticated")
	})
}

func TestStrictCommRejectsInvalidServerConfiguration(t *testing.T) {
	policy := authenticatedCommPolicy(t)
	ca := newAuthority(t)
	serverCert := ca.leaf(t, x509.ExtKeyUsageServerAuth, false)
	serverPEM, serverKey := pemPair(t, serverCert)
	classicalPEM, classicalKey := pemPair(t, ca.classicalLeaf(t, x509.ExtKeyUsageServerAuth))

	for _, test := range []struct {
		name  string
		opts  comm.SecureOptions
		cause string
	}{
		{"TLS disabled", comm.SecureOptions{TransportPolicy: policy}, "requires TLS"},
		{"invalid policy", comm.SecureOptions{UseTLS: true, TransportPolicy: &pqtransport.Policy{}}, "authenticated"},
		{"classical server credential", comm.SecureOptions{
			UseTLS: true, Certificate: classicalPEM, Key: classicalKey, TransportPolicy: policy,
		}, "invalid strict server certificate"},
		{"missing mTLS roots", comm.SecureOptions{
			UseTLS: true, RequireClientCert: true, Certificate: serverPEM, Key: serverKey, TransportPolicy: policy,
		}, "missing TLS client trust anchors"},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, err := comm.NewGRPCServer("127.0.0.1:0", comm.ServerConfig{SecOpts: test.opts})
			require.Nil(t, server)
			require.ErrorContains(t, err, test.cause)
		})
	}
}
