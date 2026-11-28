// SPDX-License-Identifier: Apache-2.0

package peer

import (
	"testing"

	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation/testfixture"
	"github.com/stretchr/testify/require"
)

func TestPQ40B1PeerRejectsUnmanagedCapabilityGenesis(t *testing.T) {
	fixture := testfixture.New(t)
	p := &Peer{CryptoProvider: fixture.Crypto}
	err := p.CreateChannel(testfixture.ChannelID, testfixture.TransportGenesis(t), nil, nil, nil)
	require.ErrorContains(t, err, "requires authenticated managed channel protection")
}
