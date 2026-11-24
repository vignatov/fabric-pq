/*
Copyright 2021 IBM All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gateway

import (
	"context"
	"errors"
	"math"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/hyperledger/fabric-lib-go/bccsp/sw"
	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	dp "github.com/hyperledger/fabric-protos-go-apiv2/discovery"
	"github.com/hyperledger/fabric-protos-go-apiv2/msp"
	"github.com/hyperledger/fabric/common/channelconfig"
	"github.com/hyperledger/fabric/common/crypto/tlsgen"
	"github.com/hyperledger/fabric/core/config/configtest"
	"github.com/hyperledger/fabric/internal/configtxgen/encoder"
	"github.com/hyperledger/fabric/internal/configtxgen/genesisconfig"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

const channelName = "mychannel"

func TestSorter(t *testing.T) {
	newState := func(address string, height uint64) *endorserState {
		return &endorserState{
			endorser: &endorser{endpointConfig: &endpointConfig{address: address}},
			height:   height,
		}
	}

	for _, test := range []struct {
		name     string
		host     string
		a, b     *endorserState
		expected int
	}{
		{
			name: "higher remote peer precedes lower host peer", host: "host",
			a: newState("remote", 5), b: newState("host", 4), expected: -1,
		},
		{
			name: "higher host peer precedes lower remote peer", host: "host",
			a: newState("host", 5), b: newState("remote", 4), expected: -1,
		},
		{
			name: "host peer wins at equal height", host: "host",
			a: newState("host", 4), b: newState("remote", 4), expected: -1,
		},
		{
			name: "remote peers at equal height compare equal", host: "host",
			a: newState("remote1", 4), b: newState("remote2", 4), expected: 0,
		},
		{
			name: "host peers at equal height compare equal", host: "host",
			a: newState("host", 4), b: newState("host", 4), expected: 0,
		},
		{
			name: "empty host orders by height",
			a:    newState("remote1", 5), b: newState("remote2", 4), expected: -1,
		},
		{
			name: "empty host leaves equal height remote peers equal",
			a:    newState("remote1", 4), b: newState("remote2", 4), expected: 0,
		},
		{
			name: "full uint64 height range", host: "host",
			a: newState("remote", math.MaxUint64), b: newState("host", 0), expected: -1,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			compare := sorter(test.host)
			require.Equal(t, test.expected, compare(test.a, test.b))
			require.Equal(t, -test.expected, compare(test.b, test.a))
			require.Zero(t, compare(test.a, test.a))
			require.Zero(t, compare(test.b, test.b))
		})
	}
}

func TestSorterPeerOrdering(t *testing.T) {
	host := &endorser{endpointConfig: &endpointConfig{address: "host"}}
	remote := &endorser{endpointConfig: &endpointConfig{address: "remote"}}
	higher := &endorserState{endorser: remote, height: 5}
	local := &endorserState{endorser: host, height: 4}
	equal := &endorserState{endorser: remote, height: 4}
	lower := &endorserState{endorser: remote, height: 3}
	want := []*endorserState{higher, local, equal, lower}

	// Check every input ordering so host preference cannot depend on its position.
	for a := range want {
		for b := range want {
			if b == a {
				continue
			}
			for c := range want {
				if c == a || c == b {
					continue
				}
				for d := range want {
					if d == a || d == b || d == c {
						continue
					}
					peers := []*endorserState{want[a], want[b], want[c], want[d]}
					slices.SortFunc(peers, sorter(host.address))
					require.Equal(t, want, peers, "input order: %v", []int{a, b, c, d})
				}
			}
		}
	}
}

func TestOrdererCache(t *testing.T) {
	def := &testDef{
		config: buildConfig(t, []string{"orderer1"}),
	}
	test := prepareTest(t, def)

	orderers, n, err := test.server.registry.orderers(channelName)
	require.NoError(t, err)
	require.Len(t, orderers, 1)
	require.Len(t, orderers[0].tlsRootCerts, 3) // 1 tlsrootCA + 2 tlsintermediateCAs
	require.Equal(t, 1, n)

	// trigger the config update callback, updating the orderers
	bundle, err := createChannelConfigBundle(channelName, []string{"orderer1:7050", "orderer2:7050", "orderer3:7050"})
	require.NoError(t, err)
	test.server.registry.configUpdate(bundle)
	orderers, n, err = test.server.registry.orderers(channelName)
	require.NoError(t, err)
	require.Len(t, orderers, 3)
	require.Len(t, orderers[2].tlsRootCerts, 2) // 1 tlsrootCA + 1 tlsintermediateCA from sampleconfig folder
	require.Equal(t, 3, n)
}

func TestPQ40EGatewayOrdererStaging(t *testing.T) {
	test := prepareTest(t, &testDef{config: buildConfig(t, []string{"orderer1", "orderer2"})})
	registry := test.server.registry
	old, _, err := registry.orderers(channelName)
	require.NoError(t, err)
	require.Len(t, old, 2)
	closed := false
	old[0].closeConnection = func() error { closed = true; return nil }

	otherBundle, err := createChannelConfigBundle("other-channel", []string{"other:7050"})
	require.NoError(t, err)
	registry.configUpdate(otherBundle)
	other, _, err := registry.orderers("other-channel")
	require.NoError(t, err)
	require.Len(t, other, 1)
	otherClosed := false
	other[0].closeConnection = func() error { otherClosed = true; return nil }

	candidateBundle, err := createChannelConfigBundle(channelName, []string{"orderer2:7050"})
	require.NoError(t, err)
	channel, candidate := stageOrdererConfig(candidateBundle)
	require.Equal(t, channelName, channel)
	require.Len(t, candidate, 1)
	publish, err := registry.prepareProtectedConfigUpdate(candidateBundle)
	require.NoError(t, err)
	before, _, err := registry.orderers(channelName)
	require.NoError(t, err)
	require.Equal(t, old, before)
	require.False(t, closed, "preparation must not close an active connection")

	require.NoError(t, publish())
	after, _, err := registry.orderers(channelName)
	require.NoError(t, err)
	require.Len(t, after, 1)
	require.True(t, closed, "publication must retire the removed connection")
	require.False(t, otherClosed, "publication must preserve unrelated connections")
}

func TestPQ40EGatewayRetiresChangedTLSRoots(t *testing.T) {
	test := prepareTest(t, &testDef{config: buildConfig(t, []string{"orderer1"})})
	registry := test.server.registry
	old, _, err := registry.orderers(channelName)
	require.NoError(t, err)
	require.Len(t, old, 1)
	oldClosed := false
	old[0].closeConnection = func() error { oldClosed = true; return nil }

	otherBundle, err := createChannelConfigBundle("other-channel", []string{old[0].address})
	require.NoError(t, err)
	registry.configUpdate(otherBundle)
	other, _, err := registry.orderers("other-channel")
	require.NoError(t, err)
	require.Len(t, other, 1)
	otherClosed := false
	other[0].closeConnection = func() error { otherClosed = true; return nil }
	require.NotSame(t, old[0], other[0])

	newCA, err := tlsgen.NewCA()
	require.NoError(t, err)
	candidate := []*endpointConfig{{address: old[0].address, mspid: old[0].mspid, tlsRootCerts: [][]byte{newCA.CertBytes()}}}
	before, _, err := registry.orderers(channelName)
	require.NoError(t, err)
	require.Same(t, old[0], before[0])
	require.False(t, oldClosed)
	require.NoError(t, registry.publishOrdererConfig(channelName, candidate))
	require.True(t, oldClosed)
	require.False(t, otherClosed)
	after, _, err := registry.orderers(channelName)
	require.NoError(t, err)
	require.Len(t, after, 1)
	require.NotSame(t, old[0], after[0])
	require.Equal(t, candidate[0].tlsRootCerts, after[0].tlsRootCerts)
}

func TestPQ40EGatewayRetriesFailedConnectionRetirement(t *testing.T) {
	test := prepareTest(t, &testDef{config: buildConfig(t, []string{"orderer1"})})
	registry := test.server.registry
	old, _, err := registry.orderers(channelName)
	require.NoError(t, err)
	require.Len(t, old, 1)
	oldKey := cacheKey(channelName, old[0].endpointConfig)
	attempts := 0
	old[0].closeConnection = func() error {
		attempts++
		if attempts == 1 {
			return errors.New("close failed")
		}
		return nil
	}
	newCA, err := tlsgen.NewCA()
	require.NoError(t, err)
	candidate := []*endpointConfig{{address: old[0].address, mspid: old[0].mspid, tlsRootCerts: [][]byte{newCA.CertBytes()}}}
	require.ErrorContains(t, registry.publishOrdererConfig(channelName, candidate), "close failed")
	_, found := registry.broadcastClients.Load(oldKey)
	require.True(t, found, "failed retirement must remain retryable")
	current, _, err := registry.orderers(channelName)
	require.NoError(t, err)
	require.Len(t, current, 1)
	require.NotSame(t, old[0], current[0], "failed retirement must not make old roots current")
	require.NoError(t, registry.publishOrdererConfig(channelName, candidate))
	_, found = registry.broadcastClients.Load(oldKey)
	require.False(t, found)
	require.Equal(t, 2, attempts)
}

func TestPQ40EGatewayEmptyPublishedEndpointsRetireConnections(t *testing.T) {
	test := prepareTest(t, &testDef{config: buildConfig(t, []string{"orderer1"})})
	registry := test.server.registry
	old, _, err := registry.orderers(channelName)
	require.NoError(t, err)
	require.Len(t, old, 1)
	closed := false
	old[0].closeConnection = func() error { closed = true; return nil }
	require.NoError(t, registry.publishOrdererConfig(channelName, nil))
	require.True(t, closed)
	current, count, err := registry.orderers(channelName)
	require.NoError(t, err)
	require.Empty(t, current)
	require.Zero(t, count, "an approved empty snapshot must not fall back to discovery")
}

func TestPQ40EGatewayRejectsConnectionFromSupersededConfig(t *testing.T) {
	test := prepareTest(t, &testDef{config: buildConfig(t, []string{"orderer1"})})
	registry := test.server.registry
	started := make(chan struct{})
	resume := make(chan struct{})
	resumeDial := sync.OnceFunc(func() { close(resume) })
	defer resumeDial()
	registry.endpointFactory.dialer = func(context.Context, string, ...grpc.DialOption) (*grpc.ClientConn, error) {
		close(started)
		<-resume
		return nil, nil
	}
	result := make(chan error, 1)
	go func() {
		_, _, err := registry.orderers(channelName)
		result <- err
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("orderer connection did not start")
	}
	newCA, err := tlsgen.NewCA()
	require.NoError(t, err)
	candidate := []*endpointConfig{{address: "orderer1:7050", mspid: "msp1", tlsRootCerts: [][]byte{newCA.CertBytes()}}}
	require.NoError(t, registry.publishOrdererConfig(channelName, candidate))
	resumeDial()
	select {
	case err := <-result:
		require.ErrorContains(t, err, "configuration changed during connection setup")
	case <-time.After(5 * time.Second):
		t.Fatal("superseded connection did not return")
	}
}

func TestStaleOrdererConnections(t *testing.T) {
	def := &testDef{
		config: buildConfig(t, []string{"orderer1", "orderer2", "orderer3"}),
	}
	test := prepareTest(t, def)
	initial, err := createChannelConfigBundle(channelName, []string{"orderer1:7050", "orderer2:7050", "orderer3:7050"})
	require.NoError(t, err)
	test.server.registry.configUpdate(initial)

	orderers, n, err := test.server.registry.orderers(channelName)
	require.NoError(t, err)
	require.Len(t, orderers, 3)
	require.Equal(t, 3, n)

	closed := make([]bool, len(orderers))
	for i, o := range orderers {
		o.closeConnection = func(index int) func() error {
			return func() error {
				closed[index] = true
				return nil
			}
		}(i)
	}
	// trigger the config update callback, updating the orderers
	bundle, err := createChannelConfigBundle(channelName, []string{"orderer1:7050", "orderer3:7050"})
	require.NoError(t, err)
	test.server.registry.configUpdate(bundle)
	orderers, _, err = test.server.registry.orderers(channelName)
	require.NoError(t, err)
	require.Len(t, orderers, 2)
	require.False(t, closed[0])
	require.True(t, closed[1])
	require.False(t, closed[2])
}

func TestStaleMultiChannelOrdererConnections(t *testing.T) {
	channel1 := "channel1"

	def := &testDef{
		config: buildConfig(t, []string{"orderer1", "orderer2"}),
	}
	test := prepareTest(t, def)

	orderers, n, err := test.server.registry.orderers(channelName)
	require.NoError(t, err)
	require.Len(t, orderers, 2)
	require.Equal(t, 2, n)
	firstChannelClosed := false
	orderers[0].closeConnection = func() error { firstChannelClosed = true; return nil }

	// trigger the config update callback, updating the orderers
	bundle, err := createChannelConfigBundle(channel1, []string{"orderer1:7050", "orderer3:7050", "orderer4:7050"})
	require.NoError(t, err)
	test.server.registry.configUpdate(bundle)
	orderers, n, err = test.server.registry.orderers(channel1)
	require.NoError(t, err)
	require.Len(t, orderers, 3)
	require.Equal(t, 3, n)

	closed := make([]bool, len(orderers))
	for i, o := range orderers {
		o.closeConnection = func(index int) func() error {
			return func() error {
				closed[index] = true
				return nil
			}
		}(i)
	}

	// Removing endpoints retires this channel's connections independently of
	// connections to the same address used by other channels.
	bundle, err = createChannelConfigBundle(channel1, []string{"orderer4:7050"})
	require.NoError(t, err)
	test.server.registry.configUpdate(bundle)
	orderers, n, err = test.server.registry.orderers(channel1)
	require.NoError(t, err)
	require.Len(t, orderers, 1)
	require.Equal(t, 1, n)

	require.True(t, closed[0])  // orderer1 on channel1
	require.True(t, closed[1])  // orderer3
	require.False(t, closed[2]) // orderer4
	require.False(t, firstChannelClosed)
}

func buildConfig(t *testing.T, orderers []string) *dp.ConfigResult {
	ca, err := tlsgen.NewCA()
	require.NoError(t, err)
	ica1, err := ca.NewIntermediateCA()
	require.NoError(t, err)
	ica2, err := ica1.NewIntermediateCA()
	require.NoError(t, err)
	var endpoints []*dp.Endpoint
	for _, o := range orderers {
		endpoints = append(endpoints, &dp.Endpoint{Host: o, Port: 7050})
	}

	return &dp.ConfigResult{
		Orderers: map[string]*dp.Endpoints{
			"msp1": {
				Endpoint: endpoints,
			},
		},
		Msps: map[string]*msp.FabricMSPConfig{
			"msp1": {
				TlsRootCerts:         [][]byte{ca.CertBytes()},
				TlsIntermediateCerts: [][]byte{ica1.CertBytes(), ica2.CertBytes()},
			},
		},
	}
}

func createChannelConfigBundle(channel string, endpoints []string) (*channelconfig.Bundle, error) {
	conf := genesisconfig.Load(genesisconfig.SampleDevModeSoloProfile, configtest.GetDevConfigDir())
	conf.Capabilities = map[string]bool{"V2_0": true}
	conf.Orderer.Organizations[0].OrdererEndpoints = endpoints

	cg, err := encoder.NewChannelGroup(conf)
	if err != nil {
		return nil, err
	}

	cryptoProvider, err := sw.NewDefaultSecurityLevelWithKeystore(sw.NewDummyKeyStore())
	if err != nil {
		return nil, err
	}

	return channelconfig.NewBundle(channel, &cb.Config{ChannelGroup: cg}, cryptoProvider)
}
