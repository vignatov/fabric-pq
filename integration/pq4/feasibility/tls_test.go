/*
SPDX-License-Identifier: Apache-2.0
*/

package feasibility

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/peer"
)

type authority struct {
	cert *x509.Certificate
	key  *mldsa.PrivateKey
	pool *x509.CertPool
}

func assertMLDSA65Identifiers(t *testing.T, cert *x509.Certificate) {
	t.Helper()
	want := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		Key       asn1.BitString
	}
	rest, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &spki)
	require.NoError(t, err)
	require.Empty(t, rest)
	require.Equal(t, want, spki.Algorithm.Algorithm)
	require.Empty(t, spki.Algorithm.Parameters.FullBytes)

	var wire struct {
		TBS       asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}
	rest, err = asn1.Unmarshal(cert.Raw, &wire)
	require.NoError(t, err)
	require.Empty(t, rest)
	require.Equal(t, want, wire.Algorithm.Algorithm)
	require.Empty(t, wire.Algorithm.Parameters.FullBytes)
}

func newAuthority(t *testing.T) authority {
	t.Helper()

	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "PQ4 feasibility CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	require.Equal(t, x509.MLDSA65, cert.SignatureAlgorithm)
	assertMLDSA65Identifiers(t, cert)
	require.NoError(t, cert.CheckSignatureFrom(cert))
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return authority{cert: cert, key: key, pool: pool}
}

func (ca authority) leaf(t *testing.T, usage x509.ExtKeyUsage, expired bool) tls.Certificate {
	t.Helper()

	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	now := time.Now()
	notBefore, notAfter := now.Add(-time.Hour), now.Add(time.Hour)
	if expired {
		notBefore, notAfter = now.Add(-2*time.Hour), now.Add(-time.Hour)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "PQ4 feasibility leaf"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		DNSNames:     []string{"pq4.example"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, key.Public(), ca.key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	require.Equal(t, x509.MLDSA65, cert.SignatureAlgorithm)
	assertMLDSA65Identifiers(t, cert)
	require.NoError(t, cert.CheckSignatureFrom(ca.cert))
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	pair, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	)
	require.NoError(t, err)
	pair.SupportedSignatureAlgorithms = []tls.SignatureScheme{tls.MLDSA65}
	return pair
}

func (ca authority) classicalLeaf(t *testing.T, usage x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		DNSNames:     []string{"pq4.example"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	pair, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	)
	require.NoError(t, err)
	return pair
}

func configs(ca authority, server, client tls.Certificate, mutual bool) (*tls.Config, *tls.Config) {
	serverConfig := &tls.Config{
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		CurvePreferences:       []tls.CurveID{tls.X25519MLKEM768},
		Certificates:           []tls.Certificate{server},
		SessionTicketsDisabled: true,
	}
	clientConfig := &tls.Config{
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
		RootCAs:          ca.pool,
		ServerName:       "pq4.example",
	}
	if mutual {
		serverConfig.ClientAuth = tls.RequireAndVerifyClientCert
		serverConfig.ClientCAs = ca.pool
		clientConfig.Certificates = []tls.Certificate{client}
	}
	return serverConfig, clientConfig
}

type handshakeResult struct {
	state tls.ConnectionState
	err   error
}

func exchange(t *testing.T, serverConfig, clientConfig *tls.Config) (handshakeResult, handshakeResult) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	serverResult := make(chan handshakeResult, 1)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			serverResult <- handshakeResult{err: err}
			return
		}
		defer raw.Close()
		if err := raw.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			serverResult <- handshakeResult{err: err}
			return
		}
		conn := tls.Server(raw, serverConfig)
		err = conn.Handshake()
		if err == nil {
			_, err = io.ReadFull(conn, make([]byte, 1))
		}
		if err == nil {
			_, err = conn.Write([]byte{1})
		}
		serverResult <- handshakeResult{state: conn.ConnectionState(), err: err}
	}()

	raw, err := net.DialTimeout("tcp", listener.Addr().String(), 5*time.Second)
	require.NoError(t, err)
	defer raw.Close()
	require.NoError(t, raw.SetDeadline(time.Now().Add(5*time.Second)))
	conn := tls.Client(raw, clientConfig)
	err = conn.Handshake()
	if err == nil {
		_, err = conn.Write([]byte{1})
	}
	if err == nil {
		_, err = io.ReadFull(conn, make([]byte, 1))
	}
	clientResult := handshakeResult{state: conn.ConnectionState(), err: err}
	return <-serverResult, clientResult
}

func assertStrictState(t *testing.T, state tls.ConnectionState, wantPeer bool) {
	t.Helper()
	require.True(t, state.HandshakeComplete)
	require.Equal(t, uint16(tls.VersionTLS13), state.Version)
	require.Equal(t, tls.X25519MLKEM768, state.CurveID)
	require.False(t, state.DidResume)
	if wantPeer {
		require.NotEmpty(t, state.VerifiedChains)
		require.Equal(t, x509.MLDSA65, state.PeerCertificates[0].SignatureAlgorithm)
		publicKey, ok := state.PeerCertificates[0].PublicKey.(*mldsa.PublicKey)
		require.True(t, ok)
		require.Equal(t, mldsa.MLDSA65(), publicKey.Parameters())
	}
}

func TestNativeHybridMLDSAHandshake(t *testing.T) {
	ca := newAuthority(t)
	server := ca.leaf(t, x509.ExtKeyUsageServerAuth, false)
	client := ca.leaf(t, x509.ExtKeyUsageClientAuth, false)

	for _, mutual := range []bool{false, true} {
		t.Run(fmt.Sprintf("mutual=%t", mutual), func(t *testing.T) {
			serverConfig, clientConfig := configs(ca, server, client, mutual)
			serverResult, clientResult := exchange(t, serverConfig, clientConfig)
			require.NoError(t, serverResult.err)
			require.NoError(t, clientResult.err)
			assertStrictState(t, serverResult.state, mutual)
			assertStrictState(t, clientResult.state, true)
			t.Logf("TLS 1.3, actual group %s, ML-DSA-65-only CertificateVerify, mutual=%t",
				clientResult.state.CurveID, mutual)
		})
	}
	t.Run("IP subject alternative name", func(t *testing.T) {
		serverConfig, clientConfig := configs(ca, server, client, false)
		clientConfig.ServerName = "127.0.0.1"
		serverResult, clientResult := exchange(t, serverConfig, clientConfig)
		require.NoError(t, serverResult.err)
		require.NoError(t, clientResult.err)
		assertStrictState(t, clientResult.state, true)
	})
}

func TestNativeTLSRejections(t *testing.T) {
	ca := newAuthority(t)
	otherCA := newAuthority(t)
	server := ca.leaf(t, x509.ExtKeyUsageServerAuth, false)
	client := ca.leaf(t, x509.ExtKeyUsageClientAuth, false)
	expired := ca.leaf(t, x509.ExtKeyUsageServerAuth, true)
	wrongServerUsage := ca.leaf(t, x509.ExtKeyUsageClientAuth, false)
	wrongClientUsage := ca.leaf(t, x509.ExtKeyUsageServerAuth, false)
	untrustedClient := otherCA.leaf(t, x509.ExtKeyUsageClientAuth, false)
	invalidSignature := server
	invalidSignature.Certificate = [][]byte{append([]byte(nil), server.Certificate[0]...)}
	invalidSignature.Certificate[0][len(invalidSignature.Certificate[0])-1] ^= 1
	invalidSignature.Leaf = nil

	tests := []struct {
		name   string
		mutual bool
		change func(*tls.Config, *tls.Config)
		cause  string
	}{
		{"TLS12", false, func(_ *tls.Config, c *tls.Config) {
			c.MinVersion, c.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
		}, "unsupported versions"},
		{"TLS12 server", false, func(s *tls.Config, _ *tls.Config) {
			s.MinVersion, s.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
		}, "unsupported versions"},
		{"classical key exchange", false, func(_ *tls.Config, c *tls.Config) {
			c.CurvePreferences = []tls.CurveID{tls.X25519}
		}, "no key exchanges supported"},
		{"classical server key exchange", false, func(s *tls.Config, _ *tls.Config) {
			s.CurvePreferences = []tls.CurveID{tls.X25519}
		}, "no key exchanges supported"},
		{"untrusted server CA", false, func(_ *tls.Config, c *tls.Config) { c.RootCAs = otherCA.pool }, "unknown authority"},
		{"wrong hostname", false, func(_ *tls.Config, c *tls.Config) { c.ServerName = "wrong.example" }, "not wrong.example"},
		{"wrong IP", false, func(_ *tls.Config, c *tls.Config) { c.ServerName = "127.0.0.2" }, "not 127.0.0.2"},
		{"expired server", false, func(s *tls.Config, _ *tls.Config) { s.Certificates = []tls.Certificate{expired} }, "expired"},
		{"wrong server usage", false, func(s *tls.Config, _ *tls.Config) { s.Certificates = []tls.Certificate{wrongServerUsage} }, "incompatible key usage"},
		{"invalid server signature", false, func(s *tls.Config, _ *tls.Config) { s.Certificates = []tls.Certificate{invalidSignature} }, "ML-DSA verification failure"},
		{"missing client certificate", true, func(_ *tls.Config, c *tls.Config) { c.Certificates = nil }, "client didn't provide a certificate"},
		{"wrong client usage", true, func(_ *tls.Config, c *tls.Config) { c.Certificates = []tls.Certificate{wrongClientUsage} }, "incompatible key usage"},
		{"untrusted client CA", true, func(_ *tls.Config, c *tls.Config) { c.Certificates = []tls.Certificate{untrustedClient} }, "unknown authority"},
		{"wrong server signature scheme", false, func(s *tls.Config, _ *tls.Config) {
			cert := server
			cert.SupportedSignatureAlgorithms = []tls.SignatureScheme{tls.Ed25519}
			s.Certificates = []tls.Certificate{cert}
		}, "ML-DSA certificates require TLS 1.3"},
		{"wrong client signature scheme", true, func(_ *tls.Config, c *tls.Config) {
			cert := client
			cert.SupportedSignatureAlgorithms = []tls.SignatureScheme{tls.Ed25519}
			c.Certificates = []tls.Certificate{cert}
		}, "client didn't provide a certificate"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			serverConfig, clientConfig := configs(ca, server, client, test.mutual)
			test.change(serverConfig, clientConfig)
			serverResult, clientResult := exchange(t, serverConfig, clientConfig)
			require.Error(t, serverResult.err)
			require.Error(t, clientResult.err)
			combined := fmt.Sprintf("server: %v; client: %v", serverResult.err, clientResult.err)
			require.Contains(t, combined, test.cause)
			t.Log(combined)
		})
	}

	t.Run("mismatched private key", func(t *testing.T) {
		keyDER, err := x509.MarshalPKCS8PrivateKey(otherCA.key)
		require.NoError(t, err)
		_, err = tls.X509KeyPair(
			pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate[0]}),
			pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		)
		require.ErrorContains(t, err, "private key does not match public key")
	})
}

func TestNativeAdditionalPeerAlgorithmCheck(t *testing.T) {
	ca := newAuthority(t)
	server := ca.leaf(t, x509.ExtKeyUsageServerAuth, false)
	client := ca.leaf(t, x509.ExtKeyUsageClientAuth, false)
	classicalServer := ca.classicalLeaf(t, x509.ExtKeyUsageServerAuth)
	classicalClient := ca.classicalLeaf(t, x509.ExtKeyUsageClientAuth)

	verifyPeer := func(state tls.ConnectionState) error {
		if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
			return errors.New("no normally verified peer chain")
		}
		key, ok := state.PeerCertificates[0].PublicKey.(*mldsa.PublicKey)
		if !ok || key.Parameters() != mldsa.MLDSA65() {
			return errors.New("peer key is not ML-DSA-65")
		}
		return nil
	}

	for _, test := range []struct {
		name        string
		server      tls.Certificate
		client      tls.Certificate
		wantFailure bool
	}{
		{"ML-DSA peers", server, client, false},
		{"classical server", classicalServer, client, true},
		{"classical client", server, classicalClient, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			serverConfig, clientConfig := configs(ca, test.server, test.client, true)
			serverConfig.VerifyConnection = verifyPeer
			clientConfig.VerifyConnection = verifyPeer
			serverResult, clientResult := exchange(t, serverConfig, clientConfig)
			if test.wantFailure {
				require.Error(t, serverResult.err)
				require.Error(t, clientResult.err)
				require.Contains(t, fmt.Sprintf("%v %v", serverResult.err, clientResult.err), "peer key is not ML-DSA-65")
				return
			}
			require.NoError(t, serverResult.err)
			require.NoError(t, clientResult.err)
			assertStrictState(t, serverResult.state, true)
			assertStrictState(t, clientResult.state, true)
		})
	}
}

func TestNativeHybridMLDSAGRPC(t *testing.T) {
	ca := newAuthority(t)
	serverConfig, clientConfig := configs(ca,
		ca.leaf(t, x509.ExtKeyUsageServerAuth, false),
		ca.leaf(t, x509.ExtKeyUsageClientAuth, false), true)
	serverConfig.NextProtos = []string{"h2"}
	clientConfig.NextProtos = []string{"h2"}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	serverStates := make(chan tls.ConnectionState, 1)
	server := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(serverConfig)),
		grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
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
		}),
	)
	healthpb.RegisterHealthServer(server, health.NewServer())
	serveErrors := make(chan error, 1)
	go func() { serveErrors <- server.Serve(listener) }()
	defer func() {
		server.Stop()
		require.NoError(t, <-serveErrors)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(ctx, listener.Addr().String(),
		grpc.WithBlock(), grpc.WithTransportCredentials(credentials.NewTLS(clientConfig)))
	require.NoError(t, err)
	defer conn.Close()
	var remote peer.Peer
	reply, err := healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{}, grpc.Peer(&remote))
	require.NoError(t, err)
	require.Equal(t, healthpb.HealthCheckResponse_SERVING, reply.Status)
	auth, ok := remote.AuthInfo.(credentials.TLSInfo)
	require.True(t, ok)
	assertStrictState(t, auth.State, true)
	assertStrictState(t, <-serverStates, true)
	require.True(t, strings.EqualFold(auth.State.NegotiatedProtocol, "h2"))
}
