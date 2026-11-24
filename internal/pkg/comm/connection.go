/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package comm

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"sync"

	"github.com/hyperledger/fabric-lib-go/common/flogging"
	"github.com/hyperledger/fabric/common/channelconfig"
	"github.com/hyperledger/fabric/msp"
	"google.golang.org/grpc/credentials"
)

var commLogger = flogging.MustGetLogger("comm")

// CredentialSupport type manages credentials used for gRPC client connections
type CredentialSupport struct {
	mutex             sync.RWMutex
	appRootCAsByChain map[string][][]byte
	serverRootCAs     [][]byte
	clientCert        tls.Certificate
}

// TrustedRootsSnapshot contains an isolated candidate for one channel.
// Preparing a snapshot does not change any active credential support state.
type TrustedRootsSnapshot struct {
	channel string
	roots   [][]byte
}

// NewCredentialSupport creates a CredentialSupport instance.
func NewCredentialSupport(rootCAs ...[]byte) *CredentialSupport {
	return &CredentialSupport{
		appRootCAsByChain: make(map[string][][]byte),
		serverRootCAs:     rootCAs,
	}
}

// SetClientCertificate sets the tls.Certificate to use for gRPC client
// connections
func (cs *CredentialSupport) SetClientCertificate(cert tls.Certificate) {
	cs.mutex.Lock()
	cs.clientCert = cert
	cs.mutex.Unlock()
}

// GetClientCertificate returns the client certificate of the CredentialSupport
func (cs *CredentialSupport) GetClientCertificate() tls.Certificate {
	cs.mutex.RLock()
	defer cs.mutex.RUnlock()
	return cs.clientCert
}

// GetPeerCredentials returns gRPC transport credentials for use by gRPC
// clients which communicate with remote peer endpoints.
func (cs *CredentialSupport) GetPeerCredentials() credentials.TransportCredentials {
	cs.mutex.RLock()
	defer cs.mutex.RUnlock()

	var appRootCAs [][]byte
	appRootCAs = append(appRootCAs, cs.serverRootCAs...)
	for _, appRootCA := range cs.appRootCAsByChain {
		appRootCAs = append(appRootCAs, appRootCA...)
	}

	certPool := x509.NewCertPool()
	for _, appRootCA := range appRootCAs {
		if !certPool.AppendCertsFromPEM(appRootCA) {
			commLogger.Warningf("Failed adding certificates to peer's client TLS trust pool")
		}
	}

	return credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cs.clientCert},
		RootCAs:      certPool,
	})
}

func (cs *CredentialSupport) AppRootCAsByChain() [][]byte {
	cs.mutex.RLock()
	defer cs.mutex.RUnlock()

	var trustedRoots [][]byte
	// iterate over all roots for all app and orderer channels
	for _, roots := range cs.appRootCAsByChain {
		for _, root := range roots {
			trustedRoots = append(trustedRoots, append([]byte(nil), root...))
		}
	}
	return trustedRoots
}

// BuildTrustedRootsForChain prepares and publishes application TLS roots for a
// channel. Protected callers must stage and publish at their activation boundary.
func (cs *CredentialSupport) BuildTrustedRootsForChain(cm channelconfig.Resources) {
	snapshot, err := PrepareTrustedRootsForChain(cm)
	if err != nil {
		commLogger.Errorf("Error preparing root CAs for channel %s (%s)", cm.ConfigtxValidator().ChannelID(), err)
		return
	}
	if err := cs.PublishTrustedRootsForChain(snapshot); err != nil {
		commLogger.Errorf("Error publishing root CAs for channel %s (%s)", cm.ConfigtxValidator().ChannelID(), err)
	}
}

// PrepareTrustedRootsForChain derives a private candidate from a bundle.
// The activation owner must authorize and durably commit the bundle before
// calling PublishTrustedRootsForChain.
func PrepareTrustedRootsForChain(cm channelconfig.Resources) (*TrustedRootsSnapshot, error) {
	appOrgMSPs := make(map[string]struct{})
	if ac, ok := cm.ApplicationConfig(); ok {
		for _, appOrg := range ac.Organizations() {
			appOrgMSPs[appOrg.MSPID()] = struct{}{}
		}
	}

	ordOrgMSPs := make(map[string]struct{})
	if ac, ok := cm.OrdererConfig(); ok {
		for _, ordOrg := range ac.Organizations() {
			ordOrgMSPs[ordOrg.MSPID()] = struct{}{}
		}
	}

	cid := cm.ConfigtxValidator().ChannelID()
	msps, err := cm.MSPManager().GetMSPs()
	if err != nil {
		return nil, err
	}

	var appRootCAs [][]byte
	for k, v := range msps {
		// we only support the fabric MSP
		if v.GetType() != msp.FABRIC {
			continue
		}

		for _, root := range v.GetTLSRootCerts() {
			// check to see of this is an app org MSP
			if _, ok := appOrgMSPs[k]; ok {
				commLogger.Debugf("adding app root CAs for MSP [%s]", k)
				appRootCAs = append(appRootCAs, append([]byte(nil), root...))
			}
		}
		for _, intermediate := range v.GetTLSIntermediateCerts() {
			// check to see of this is an app org MSP
			if _, ok := appOrgMSPs[k]; ok {
				commLogger.Debugf("adding app root CAs for MSP [%s]", k)
				appRootCAs = append(appRootCAs, append([]byte(nil), intermediate...))
			}
		}
	}

	return &TrustedRootsSnapshot{channel: cid, roots: appRootCAs}, nil
}

// PreviewTrustedRootsForChain returns the aggregate application roots that
// would result from publishing snapshot without changing active credentials.
func (cs *CredentialSupport) PreviewTrustedRootsForChain(snapshot *TrustedRootsSnapshot) ([][]byte, error) {
	if snapshot == nil {
		return nil, errors.New("trusted roots snapshot is required")
	}
	cs.mutex.RLock()
	defer cs.mutex.RUnlock()
	var roots [][]byte
	for channel, existing := range cs.appRootCAsByChain {
		if channel == snapshot.channel {
			continue
		}
		for _, root := range existing {
			roots = append(roots, append([]byte(nil), root...))
		}
	}
	for _, root := range snapshot.roots {
		roots = append(roots, append([]byte(nil), root...))
	}
	return roots, nil
}

// PublishTrustedRootsForChain makes a previously prepared snapshot visible.
// Protected callers must invoke it only at their approved publication point.
func (cs *CredentialSupport) PublishTrustedRootsForChain(snapshot *TrustedRootsSnapshot) error {
	if snapshot == nil {
		return errors.New("trusted roots snapshot is required")
	}
	roots := make([][]byte, len(snapshot.roots))
	for i, root := range snapshot.roots {
		roots[i] = append([]byte(nil), root...)
	}
	cs.mutex.Lock()
	cs.appRootCAsByChain[snapshot.channel] = roots
	cs.mutex.Unlock()
	return nil
}
