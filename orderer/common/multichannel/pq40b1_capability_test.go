// SPDX-License-Identifier: Apache-2.0

package multichannel

import (
	"testing"

	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric/common/capabilities"
	"github.com/hyperledger/fabric/common/channelconfig"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation/testfixture"
	"github.com/hyperledger/fabric/protoutil"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestPQ40B1OrdererRejectsUnmanagedCapabilityGenesis(t *testing.T) {
	fixture := testfixture.New(t)
	r := &Registrar{bccsp: fixture.Crypto}
	envelope, err := protoutil.ExtractEnvelope(testfixture.TransportGenesis(t), 0)
	require.NoError(t, err)
	_, err = r.newLedgerResources(envelope)
	require.ErrorContains(t, err, "requires authenticated managed channel protection")
}

func TestPQ40B1OrdererRejectsFabricAuthorizedCapabilityChanges(t *testing.T) {
	fixture := testfixture.New(t)
	for _, tc := range []struct {
		name    string
		genesis *cb.Block
		add     bool
	}{
		{name: "add after genesis", genesis: testfixture.Genesis(t), add: true},
		{name: "remove after genesis", genesis: testfixture.TransportGenesis(t)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := testfixture.Config(t, tc.genesis)
			next := proto.CloneOf(base)
			value := next.GetChannelGroup().GetValues()[channelconfig.CapabilitiesKey]
			if value == nil {
				value = &cb.ConfigValue{}
				next.GetChannelGroup().Values[channelconfig.CapabilitiesKey] = value
			}
			caps := &cb.Capabilities{}
			if len(value.GetValue()) != 0 {
				require.NoError(t, proto.Unmarshal(value.GetValue(), caps))
			}
			if caps.Capabilities == nil {
				caps.Capabilities = map[string]*cb.Capability{}
			}
			if tc.add {
				caps.Capabilities[capabilities.PactwayPQTransportV1] = &cb.Capability{}
			} else {
				delete(caps.Capabilities, capabilities.PactwayPQTransportV1)
			}
			value.Value = protoutil.MarshalOrPanic(caps)
			update := fixture.UpdateTo(t, base, next)
			lgr, _ := ordererActivationLedger(t, t.TempDir(), func(string) {})
			require.NoError(t, lgr.Append(tc.genesis))
			_, support := activationWriter(t, fixture, lgr, tc.genesis)
			_, err := support.ProposeConfigUpdate(update.GetLastUpdate())
			require.ErrorContains(t, err, "only be selected in genesis")
		})
	}
}
