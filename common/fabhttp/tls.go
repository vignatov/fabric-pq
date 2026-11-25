/*
Copyright IBM Corp All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package fabhttp

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
	"time"

	"github.com/hyperledger/fabric/internal/pkg/comm"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport"
)

type TLS struct {
	Enabled            bool
	CertFile           string
	KeyFile            string
	ClientCertRequired bool
	ClientCACertFiles  []string
	TimeShift          time.Duration
	TransportPolicy    *pqtransport.Policy
}

func (t TLS) Config() (*tls.Config, error) {
	if t.TransportPolicy != nil && (!t.Enabled || !t.ClientCertRequired || len(t.ClientCACertFiles) == 0) {
		return nil, errors.New("protected HTTP listener requires TLS, client authentication and client roots")
	}
	var tlsConfig *tls.Config

	if t.Enabled {
		cert, err := tls.LoadX509KeyPair(t.CertFile, t.KeyFile)
		if err != nil {
			return nil, err
		}
		caCertPool := x509.NewCertPool()
		for _, caPath := range t.ClientCACertFiles {
			caPem, err := os.ReadFile(caPath)
			if err != nil {
				return nil, err
			}
			if !caCertPool.AppendCertsFromPEM(caPem) && t.TransportPolicy != nil {
				return nil, errors.New("invalid protected HTTP client CA")
			}
		}
		tlsConfig = &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{cert},
			CipherSuites: comm.DefaultTLSCipherSuites,
			ClientCAs:    caCertPool,
		}
		if t.TimeShift > 0 {
			tlsConfig.Time = func() time.Time {
				return time.Now().Add((-1) * t.TimeShift)
			}
		}

		if t.ClientCertRequired {
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		} else {
			tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
		}
	}

	if t.TransportPolicy != nil {
		return pqtransport.ServerTLSConfig(tlsConfig, t.TransportPolicy)
	}
	return tlsConfig, nil
}
