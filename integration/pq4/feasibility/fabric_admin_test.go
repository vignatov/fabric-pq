/*
SPDX-License-Identifier: Apache-2.0
*/

package feasibility

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hyperledger/fabric/common/fabhttp"
	"github.com/hyperledger/fabric/internal/osnadmin"
	"github.com/stretchr/testify/require"
)

func TestFabricAdminMLDSACompatibility(t *testing.T) {
	ca := newAuthority(t)
	serverCert := ca.leaf(t, x509.ExtKeyUsageServerAuth, false)
	clientCert := ca.leaf(t, x509.ExtKeyUsageClientAuth, false)
	serverPEM, serverKey := pemPair(t, serverCert)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})
	dir := t.TempDir()
	certPath, keyPath, caPath := filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key"), filepath.Join(dir, "ca.crt")
	require.NoError(t, os.WriteFile(certPath, serverPEM, 0o600))
	require.NoError(t, os.WriteFile(keyPath, serverKey, 0o600))
	require.NoError(t, os.WriteFile(caPath, caPEM, 0o600))

	states := make(chan tls.ConnectionState, 2)
	server := fabhttp.NewServer(fabhttp.Options{
		ListenAddress: "127.0.0.1:0",
		TLS: fabhttp.TLS{
			Enabled:            true,
			CertFile:           certPath,
			KeyFile:            keyPath,
			ClientCertRequired: true,
			ClientCACertFiles:  []string{caPath},
		},
	})
	server.RegisterHandler("/participation/v1/channels", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		states <- *r.TLS
		w.WriteHeader(http.StatusOK)
	}), true)
	require.NoError(t, server.Start())
	defer func() { require.NoError(t, server.Stop()) }()

	url := "https://" + server.Addr()
	response, err := osnadmin.ListAllChannels(url, ca.pool, clientCert)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode)
	assertStrictState(t, *response.TLS, true)
	require.NoError(t, response.Body.Close())
	assertStrictState(t, <-states, true)

	_, classicalClient := configs(ca, serverCert, clientCert, true)
	classicalClient.ServerName = "127.0.0.1"
	classicalClient.CurvePreferences = []tls.CurveID{tls.X25519}
	transport := &http.Transport{TLSClientConfig: classicalClient, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	response, err = httpClient.Get(url + "/participation/v1/channels")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode)
	require.Equal(t, tls.X25519, response.TLS.CurveID)
	require.NotEmpty(t, response.TLS.VerifiedChains)
	_, err = io.Copy(io.Discard, response.Body)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	serverState := <-states
	require.Equal(t, tls.X25519, serverState.CurveID)
	require.NotEmpty(t, serverState.VerifiedChains)
	t.Log("baseline admin listener accepted an X25519-only client")
}
