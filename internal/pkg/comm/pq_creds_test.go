/*
SPDX-License-Identifier: Apache-2.0
*/

package comm

import (
	"context"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/hyperledger/fabric-lib-go/common/metrics/disabled"
	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric/internal/pkg/comm/testpb"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func strictServerFixture(t *testing.T) (SecureOptions, *x509.CertPool) {
	t.Helper()
	signer, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	public, ok := signer.Public().(*mldsa.PublicKey)
	require.True(t, ok)
	payload, err := json.Marshal(pqtransport.Document{
		Network: "network", Node: "node", Version: 1, Profile: pqtransport.ProfileV1,
	})
	require.NoError(t, err)
	signature, err := signer.Sign(rand.Reader, payload, nil)
	require.NoError(t, err)
	policy, err := pqtransport.Authenticate(payload, signature, public,
		&pqtransport.Checkpoint{Version: 1, Digest: sha256.Sum256(payload)}, "network", "node")
	require.NoError(t, err)

	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		DNSNames:              []string{"pq.example"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	root := x509.NewCertPool()
	require.True(t, root.AppendCertsFromPEM(certPEM))
	return SecureOptions{UseTLS: true, Certificate: certPEM, Key: keyPEM, TransportPolicy: policy}, root
}

func TestStrictServerCredentialsClone(t *testing.T) {
	options, root := strictServerFixture(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	server, err := NewGRPCServerFromListener(listener, ServerConfig{SecOpts: options})
	require.NoError(t, err)
	original := NewServerTransportCredentials(server.tls, nil)
	directFactoryConfig := server.tls.Config()
	directFactory := NewServerTransportCredentials(NewTLSConfig(&directFactoryConfig), nil)

	for _, test := range []struct {
		name  string
		creds credentials.TransportCredentials
	}{
		{"original", original},
		{"clone", original.Clone()},
		{"direct factory", directFactory},
	} {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, "1.3", test.creds.Info().SecurityVersion)
			for _, attempt := range []struct {
				name  string
				edit  func(*tls.Config)
				cause string
			}{
				{"approved", func(*tls.Config) {}, ""},
				{"TLS 1.2", func(c *tls.Config) { c.MinVersion, c.MaxVersion = tls.VersionTLS12, tls.VersionTLS12 }, "unsupported versions"},
				{"classical key exchange", func(c *tls.Config) { c.CurvePreferences = []tls.CurveID{tls.X25519} }, "key exchange"},
			} {
				t.Run(attempt.name, func(t *testing.T) {
					lis, err := net.Listen("tcp", "127.0.0.1:0")
					require.NoError(t, err)
					defer lis.Close()
					results := make(chan error, 1)
					go func() {
						raw, err := lis.Accept()
						if err != nil {
							results <- err
							return
						}
						conn, _, err := test.creds.ServerHandshake(raw)
						if conn != nil {
							_ = conn.Close()
						} else {
							_ = raw.Close()
						}
						results <- err
					}()
					client := &tls.Config{
						RootCAs: root, ServerName: "pq.example",
						MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
						CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
					}
					attempt.edit(client)
					conn, clientErr := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", lis.Addr().String(), client)
					if conn != nil {
						require.Equal(t, tls.X25519MLKEM768, conn.ConnectionState().CurveID)
						_ = conn.Close()
					}
					serverErr := <-results
					if attempt.cause == "" {
						require.NoError(t, clientErr)
						require.NoError(t, serverErr)
					} else {
						require.Error(t, clientErr)
						require.ErrorContains(t, serverErr, attempt.cause)
					}
				})
			}
		})
	}
}

type protectedStreamingService struct {
	testpb.UnimplementedEmptyServiceServer
	generation context.Context
	sending    chan struct{}
	released   chan struct{}
	admitted   chan bool
}

func (s *protectedStreamingService) EmptyStream(stream testpb.EmptyService_EmptyStreamServer) error {
	ok := RetainProtectedStream(stream.Context(), s.generation, func() { close(s.released) })
	s.admitted <- ok
	if !ok {
		return context.Canceled
	}
	payload := &cb.Envelope{Payload: make([]byte, 1<<20)}
	if err := stream.SendMsg(payload); err != nil {
		return err
	}
	close(s.sending)
	// With no client reads, this write waits for stream flow control.
	return stream.SendMsg(payload)
}

func TestPQ40EStrictStreamRevocationUnblocksSend(t *testing.T) {
	options, roots := strictServerFixture(t)
	server, err := NewGRPCServer("127.0.0.1:0", ServerConfig{
		SecOpts: options, ServerStatsHandler: NewServerStatsHandler(&disabled.Provider{}),
	})
	require.NoError(t, err)
	generation, revoke := context.WithCancel(t.Context())
	defer revoke()
	service := &protectedStreamingService{
		generation: generation, sending: make(chan struct{}), released: make(chan struct{}), admitted: make(chan bool, 1),
	}
	testpb.RegisterEmptyServiceServer(server.Server(), service)
	go server.Start()
	t.Cleanup(server.Stop)
	tlsConfig, err := pqtransport.ClientTLSConfig(&tls.Config{RootCAs: roots, ServerName: "pq.example"}, options.TransportPolicy)
	require.NoError(t, err)
	client, err := grpc.NewClient(server.Address(), grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		grpc.WithStaticStreamWindowSize(64<<10))
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	stream, err := testpb.NewEmptyServiceClient(client).EmptyStream(ctx)
	require.NoError(t, err)
	require.NoError(t, stream.Send(&testpb.Empty{}))
	select {
	case admitted := <-service.admitted:
		require.True(t, admitted, "strict transport did not expose revocation")
	case <-ctx.Done():
		t.Fatal("protected stream did not reach the server")
	}
	select {
	case <-service.sending:
	case <-ctx.Done():
		t.Fatal("first message did not enter the HTTP/2 queue")
	}
	select {
	case <-service.released:
		t.Fatal("stream released admission while the client was stalled")
	default:
	}
	revoke()
	select {
	case <-service.released:
	case <-ctx.Done():
		t.Fatal("transport did not drain the blocked send on generation closure")
	}
}
