//go:build linux

/*
SPDX-License-Identifier: Apache-2.0
*/

package multichannel

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/hyperledger/fabric-lib-go/common/metrics/disabled"
	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric/common/channelconfig"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation/testfixture"
	"github.com/hyperledger/fabric/orderer/common/localconfig"
	"github.com/hyperledger/fabric/protoutil"
	"github.com/stretchr/testify/require"
)

func TestPQ40EOrdererCallbacksWaitForAuthorization(t *testing.T) {
	fixture := testfixture.New(t)
	genesis := testfixture.Genesis(t)
	base := testfixture.Config(t, genesis)
	state := t.TempDir()
	store, err := activation.OpenStore(state, nil)
	require.NoError(t, err)
	fixture.Provision(t, store, base)
	controller := fixture.Channel(store, activation.Ledger{})
	anchor := filepath.Join(state, "policy-key")
	require.NoError(t, os.WriteFile(anchor, controller.Signer.Bytes(), 0o600))
	ledgerDir := t.TempDir()
	factory := newFactory(ledgerDir)
	t.Cleanup(factory.Close)
	var published []uint64
	r := NewRegistrar(localconfig.TopLevel{
		General: localconfig.General{PQActivation: localconfig.PQActivation{
			StateDir: state, TrustAnchor: anchor, Network: testfixture.Network, Node: testfixture.Node,
		}},
		FileLedger: localconfig.FileLedger{Location: ledgerDir},
	}, factory, fixture.Fabric, &disabled.Provider{}, fixture.Crypto, nil, func(bundle *channelconfig.Bundle) {
		published = append(published, bundle.ConfigtxValidator().Sequence())
	})
	envelope, err := protoutil.ExtractEnvelope(genesis, 0)
	require.NoError(t, err)
	resources, err := r.newLedgerResources(envelope)
	require.NoError(t, err)
	require.Empty(t, published, "candidate bundle must not invoke shared callbacks")
	require.NoError(t, resources.Append(genesis))
	channel := r.activationFor(resources)
	channel.Validate = checkResources
	require.NoError(t, channel.Recover(true))
	require.Equal(t, []uint64{0}, published)
	writer, _ := activationWriter(t, fixture, resources.ReadWriter, genesis)
	update := fixture.Update(t, base)
	block := writer.CreateNextBlock([]*cb.Envelope{fixture.Envelope(t, update)})
	err = channel.Apply(block, activation.Authorization{}, func() error {
		t.Fatal("unauthorized update reached the ledger")
		return nil
	})
	require.Error(t, err)
	require.Equal(t, []uint64{0}, published, "unauthorized candidate reached shared callbacks")
}
