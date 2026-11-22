/*
SPDX-License-Identifier: Apache-2.0
*/

package feasibility

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"path/filepath"
	"testing"

	"github.com/hyperledger/fabric-lib-go/bccsp/sw"
	mspproto "github.com/hyperledger/fabric-protos-go-apiv2/msp"
	etcdraftproto "github.com/hyperledger/fabric-protos-go-apiv2/orderer/etcdraft"
	"github.com/hyperledger/fabric/msp"
	"github.com/hyperledger/fabric/orderer/consensus/etcdraft"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestFabricMSPMLDSATrustAnchor(t *testing.T) {
	ca := newAuthority(t)
	root := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})
	nonCA := ca.leaf(t, x509.ExtKeyUsageServerAuth, false)
	nonCAPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: nonCA.Certificate[0]})

	fixture := filepath.Join("..", "..", "..", "msp", "testdata", "tls")
	base, err := msp.GetVerifyingMspConfig(fixture, "SampleOrg", "bccsp")
	require.NoError(t, err)
	fabricConfig := &mspproto.FabricMSPConfig{}
	require.NoError(t, proto.Unmarshal(base.GetConfig(), fabricConfig))
	fabricConfig.TlsIntermediateCerts = nil

	for _, test := range []struct {
		name        string
		root        []byte
		wantFailure bool
	}{
		{"ML-DSA CA", root, false},
		{"leaf is not a CA", nonCAPEM, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := proto.Clone(fabricConfig).(*mspproto.FabricMSPConfig)
			config.TlsRootCerts = [][]byte{test.root}
			encoded, err := proto.Marshal(config)
			require.NoError(t, err)
			provider, err := sw.NewDefaultSecurityLevelWithKeystore(sw.NewDummyKeyStore())
			require.NoError(t, err)
			instance, err := msp.New(&msp.BCCSPNewOpts{Version: msp.MSPv1_4_3}, provider)
			require.NoError(t, err)
			err = instance.Setup(&mspproto.MSPConfig{Type: base.GetType(), Config: encoded})
			if test.wantFailure {
				require.ErrorContains(t, err, "CA Certificate did not have the CA attribute")
				return
			}
			require.NoError(t, err)
			require.Equal(t, [][]byte{root}, instance.GetTLSRootCerts())
		})
	}
}

func TestFabricRaftMLDSACertificateMetadata(t *testing.T) {
	ca := newAuthority(t)
	server := ca.leaf(t, x509.ExtKeyUsageServerAuth, false)
	client := ca.leaf(t, x509.ExtKeyUsageClientAuth, false)
	otherCA := newAuthority(t)
	untrustedServer := otherCA.leaf(t, x509.ExtKeyUsageServerAuth, false)

	pemCert := func(cert tls.Certificate) []byte {
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	}
	metadata := &etcdraftproto.ConfigMetadata{
		Options: &etcdraftproto.Options{
			TickInterval:      "500ms",
			ElectionTick:      10,
			HeartbeatTick:     1,
			MaxInflightBlocks: 5,
		},
		Consenters: []*etcdraftproto.Consenter{{
			Host:          "pq4.example",
			Port:          7050,
			ServerTlsCert: pemCert(server),
			ClientTlsCert: pemCert(client),
		}},
	}
	opts := x509.VerifyOptions{
		Roots: ca.pool,
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
	}
	require.NoError(t, etcdraft.VerifyConfigMetadata(metadata, opts))

	metadata.Consenters[0].ServerTlsCert = pemCert(untrustedServer)
	require.ErrorContains(t, etcdraft.VerifyConfigMetadata(metadata, opts), "certificate signed by unknown authority")
}
