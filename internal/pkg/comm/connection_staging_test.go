/*
SPDX-License-Identifier: Apache-2.0
*/

package comm

import (
	"errors"
	"testing"

	"github.com/hyperledger/fabric/common/channelconfig"
	"github.com/hyperledger/fabric/common/configtx"
	"github.com/hyperledger/fabric/common/crypto/tlsgen"
	"github.com/hyperledger/fabric/msp"
	"github.com/stretchr/testify/require"
)

type stagedOrg struct{ channelconfig.ApplicationOrg }

func (stagedOrg) MSPID() string { return "test-msp" }

type stagedApplication struct{ channelconfig.Application }

func (stagedApplication) Organizations() map[string]channelconfig.ApplicationOrg {
	return map[string]channelconfig.ApplicationOrg{"org": stagedOrg{}}
}

type stagedMSP struct {
	msp.MSP
	root []byte
}

func (stagedMSP) GetType() msp.ProviderType         { return msp.FABRIC }
func (s stagedMSP) GetTLSRootCerts() [][]byte       { return [][]byte{s.root} }
func (stagedMSP) GetTLSIntermediateCerts() [][]byte { return nil }

type stagedMSPManager struct {
	msp.MSPManager
	root []byte
	err  error
}

func (s stagedMSPManager) GetMSPs() (map[string]msp.MSP, error) {
	if s.err != nil {
		return nil, s.err
	}
	return map[string]msp.MSP{"test-msp": stagedMSP{root: s.root}}, nil
}

type stagedValidator struct {
	configtx.Validator
	id string
}

func (s stagedValidator) ChannelID() string { return s.id }

type stagedConfig struct {
	channelconfig.Resources
	id   string
	root []byte
	err  error
}

func (s stagedConfig) ApplicationConfig() (channelconfig.Application, bool) {
	return stagedApplication{}, true
}
func (s stagedConfig) OrdererConfig() (channelconfig.Orderer, bool) { return nil, false }
func (s stagedConfig) MSPManager() msp.MSPManager                   { return stagedMSPManager{root: s.root, err: s.err} }
func (s stagedConfig) ConfigtxValidator() configtx.Validator        { return stagedValidator{id: s.id} }

func TestPQ40ETrustedRootsStaging(t *testing.T) {
	oldCA, err := tlsgen.NewCA()
	require.NoError(t, err)
	newCA, err := tlsgen.NewCA()
	require.NoError(t, err)
	otherCA, err := tlsgen.NewCA()
	require.NoError(t, err)
	oldRoot := oldCA.CertBytes()
	newRoot := newCA.CertBytes()
	expectedNewRoot := append([]byte(nil), newRoot...)
	otherRoot := otherCA.CertBytes()
	credentials := NewCredentialSupport()
	credentials.BuildTrustedRootsForChain(stagedConfig{id: "protected", root: oldRoot})
	credentials.BuildTrustedRootsForChain(stagedConfig{id: "other", root: otherRoot})
	before := credentials.AppRootCAsByChain()
	candidate, err := PrepareTrustedRootsForChain(stagedConfig{id: "protected", root: newRoot})
	require.NoError(t, err)
	require.ElementsMatch(t, before, credentials.AppRootCAsByChain())
	preview, err := credentials.PreviewTrustedRootsForChain(candidate)
	require.NoError(t, err)
	require.ElementsMatch(t, [][]byte{expectedNewRoot, otherRoot}, preview)
	require.ElementsMatch(t, before, credentials.AppRootCAsByChain())
	newRoot[0] ^= 1 // The prepared snapshot must not alias the source bundle.
	require.NoError(t, credentials.PublishTrustedRootsForChain(candidate))
	require.ElementsMatch(t, [][]byte{expectedNewRoot, otherRoot}, credentials.AppRootCAsByChain())
	exposed := credentials.AppRootCAsByChain()
	exposed[0][0] ^= 1
	require.ElementsMatch(t, [][]byte{expectedNewRoot, otherRoot}, credentials.AppRootCAsByChain())
	require.Error(t, credentials.PublishTrustedRootsForChain(nil))
	_, err = PrepareTrustedRootsForChain(stagedConfig{id: "protected", err: errors.New("unavailable MSP")})
	require.ErrorContains(t, err, "unavailable MSP")
	require.ElementsMatch(t, [][]byte{expectedNewRoot, otherRoot}, credentials.AppRootCAsByChain())
}
