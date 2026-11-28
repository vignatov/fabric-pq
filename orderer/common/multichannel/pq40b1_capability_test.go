// SPDX-License-Identifier: Apache-2.0

package multichannel

import (
	"testing"

	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation/testfixture"
	"github.com/hyperledger/fabric/protoutil"
	"github.com/stretchr/testify/require"
)

func TestPQ40B1OrdererRejectsUnmanagedCapabilityGenesis(t *testing.T) {
	fixture := testfixture.New(t)
	r := &Registrar{bccsp: fixture.Crypto}
	envelope, err := protoutil.ExtractEnvelope(testfixture.TransportGenesis(t), 0)
	require.NoError(t, err)
	_, err = r.newLedgerResources(envelope)
	require.ErrorContains(t, err, "requires authenticated managed channel protection")
}
