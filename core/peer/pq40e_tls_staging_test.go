//go:build linux

/*
SPDX-License-Identifier: Apache-2.0
*/

package peer

import (
	"testing"

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
	require.NoError(t, peer.publishTrustedRoots(candidate))
	preview, err := peer.CredentialSupport.PreviewTrustedRootsForChain(candidate)
	require.NoError(t, err)
	require.NotEmpty(t, preview)
	require.ElementsMatch(t, preview, peer.CredentialSupport.AppRootCAsByChain())
}
