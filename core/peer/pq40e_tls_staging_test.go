//go:build linux

/*
SPDX-License-Identifier: Apache-2.0
*/

package peer

import (
	"errors"
	"testing"
	"time"

	"github.com/hyperledger/fabric/common/channelconfig"
	"github.com/hyperledger/fabric/common/crypto/tlsgen"
	"github.com/hyperledger/fabric/internal/pkg/comm"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation/testfixture"
	"github.com/stretchr/testify/require"
)

func TestPQ40EPeerTLSRootsPublicationFailure(t *testing.T) {
	fixture := testfixture.New(t)
	genesis := testfixture.Genesis(t)
	bundle, err := channelconfig.NewBundle(testfixture.ChannelID, testfixture.Config(t, genesis), fixture.Crypto)
	require.NoError(t, err)
	candidate, err := comm.PrepareTrustedRootsForChain(bundle)
	require.NoError(t, err)

	ca, err := tlsgen.NewCA()
	require.NoError(t, err)
	pair, err := ca.NewServerCertKeyPair("127.0.0.1")
	require.NoError(t, err)
	serverConfig := comm.ServerConfig{SecOpts: comm.SecureOptions{
		UseTLS: true, Certificate: pair.Cert, Key: pair.Key,
	}}
	server, err := comm.NewGRPCServer("127.0.0.1:0", serverConfig)
	require.NoError(t, err)
	t.Cleanup(func() { _ = server.Listener().Close() })
	peer := &Peer{ServerConfig: serverConfig, CredentialSupport: comm.NewCredentialSupport(), server: server}
	require.Empty(t, peer.CredentialSupport.AppRootCAsByChain())
	peer.ServerConfig.SecOpts.ClientRootCAs = [][]byte{[]byte("invalid PEM")}
	require.Error(t, peer.publishTrustedRoots(candidate))
	require.Empty(t, peer.CredentialSupport.AppRootCAsByChain(), "failed server update must not publish candidate roots")
	peer.ServerConfig.SecOpts.ClientRootCAs = nil
	failRetirement := true
	published := false
	require.NoError(t, peer.AddProtectedConfigStage(func(*channelconfig.Bundle) (ProtectedConfigPublication, error) {
		return ProtectedConfigPublication{
			Retire: func() error {
				if failRetirement {
					return errors.New("cache retirement failed")
				}
				return nil
			},
			Publish: func() { published = true },
		}, nil
	}))
	require.ErrorContains(t, peer.publishProtectedResources(bundle), "cache retirement failed")
	require.Empty(t, peer.CredentialSupport.AppRootCAsByChain(), "failed retirement must not publish TLS roots")
	require.False(t, published)
	failRetirement = false
	require.NoError(t, peer.publishProtectedResources(bundle))
	require.True(t, published)
	require.NoError(t, peer.publishTrustedRoots(candidate))
	preview, err := peer.CredentialSupport.PreviewTrustedRootsForChain(candidate)
	require.NoError(t, err)
	require.NotEmpty(t, preview)
	require.ElementsMatch(t, preview, peer.CredentialSupport.AppRootCAsByChain())
}

func TestPQ40EProtectedStageRegistrationWaitsForPublication(t *testing.T) {
	p := &Peer{}
	started := make(chan struct{})
	finish := make(chan struct{})
	require.NoError(t, p.AddProtectedConfigStage(func(*channelconfig.Bundle) (ProtectedConfigPublication, error) {
		return ProtectedConfigPublication{Publish: func() { close(started); <-finish }}, nil
	}))
	published := make(chan error, 1)
	go func() { published <- p.publishProtectedResources(nil) }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("publication did not start")
	}
	registered := make(chan error, 1)
	go func() {
		registered <- p.AddProtectedConfigStage(func(*channelconfig.Bundle) (ProtectedConfigPublication, error) {
			return ProtectedConfigPublication{Publish: func() {}}, nil
		})
	}()
	select {
	case err := <-registered:
		require.NoError(t, err)
		t.Fatal("registration completed during an active publication")
	default:
	}
	close(finish)
	select {
	case err := <-published:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("publication did not finish")
	}
	select {
	case err := <-registered:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("registration did not resume")
	}
}
