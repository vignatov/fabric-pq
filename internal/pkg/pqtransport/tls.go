/*
SPDX-License-Identifier: Apache-2.0
*/

package pqtransport

import (
	"crypto/mldsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
)

// CheckIdentity checks the TLS endpoint key without replacing X.509 verification.
func CheckIdentity(cert *x509.Certificate) error {
	if cert == nil {
		return errors.New("missing TLS endpoint certificate")
	}
	key, ok := cert.PublicKey.(*mldsa.PublicKey)
	if !ok || key.Parameters() != mldsa.MLDSA65() {
		return errors.New("TLS endpoint identity is not ML-DSA-65")
	}
	return nil
}

// CheckCertificate checks the endpoint leaf in a local TLS credential.
func CheckCertificate(cert *tls.Certificate) error {
	if cert == nil || len(cert.Certificate) == 0 {
		return errors.New("missing TLS endpoint certificate")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("parse TLS endpoint certificate: %w", err)
	}
	return CheckIdentity(leaf)
}

func checkConnection(state tls.ConnectionState) error {
	if state.DidResume {
		return errors.New("strict TLS rejects resumed sessions")
	}
	if state.Version != tls.VersionTLS13 || state.CurveID != tls.X25519MLKEM768 {
		return errors.New("strict TLS requires TLS 1.3 and X25519MLKEM768")
	}
	return nil
}

// ServerTLSConfig applies the authenticated profile while retaining the
// listener's existing client-authentication requirement.
func ServerTLSConfig(base *tls.Config, policy *Policy) (*tls.Config, error) {
	if err := policy.Check(); err != nil {
		return nil, err
	}
	if base == nil {
		return nil, errors.New("missing server TLS configuration")
	}
	if base.GetConfigForClient != nil {
		return nil, errors.New("strict TLS does not support alternate server configurations")
	}
	if base.ClientAuth == tls.RequireAnyClientCert {
		return nil, errors.New("strict TLS requires verification of required client certificates")
	}
	if (base.ClientAuth == tls.RequireAndVerifyClientCert || base.ClientAuth == tls.VerifyClientCertIfGiven) && base.ClientCAs == nil {
		return nil, errors.New("missing TLS client trust anchors")
	}
	if base.GetCertificate == nil && len(base.Certificates) == 0 {
		return nil, errors.New("missing TLS server certificate")
	}
	for i := range base.Certificates {
		if err := CheckCertificate(&base.Certificates[i]); err != nil {
			return nil, fmt.Errorf("server certificate: %w", err)
		}
	}

	config := base.Clone()
	config.MinVersion = tls.VersionTLS13
	config.MaxVersion = tls.VersionTLS13
	config.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768}
	config.SessionTicketsDisabled = true
	if getCertificate := config.GetCertificate; getCertificate != nil {
		config.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			cert, err := getCertificate(hello)
			if err != nil {
				return nil, err
			}
			if err := CheckCertificate(cert); err != nil {
				return nil, fmt.Errorf("server certificate: %w", err)
			}
			return cert, nil
		}
	}
	previous := config.VerifyConnection
	config.VerifyConnection = func(state tls.ConnectionState) error {
		if err := checkConnection(state); err != nil {
			return err
		}
		if len(state.PeerCertificates) > 0 {
			if err := CheckIdentity(state.PeerCertificates[0]); err != nil {
				return fmt.Errorf("client certificate: %w", err)
			}
		}
		if previous != nil {
			return previous(state)
		}
		return nil
	}
	return config, nil
}

// ClientTLSConfig applies the authenticated profile without bypassing normal
// server chain and hostname verification.
func ClientTLSConfig(base *tls.Config, policy *Policy) (*tls.Config, error) {
	if err := policy.Check(); err != nil {
		return nil, err
	}
	if base == nil || base.InsecureSkipVerify || base.RootCAs == nil {
		return nil, errors.New("strict TLS requires server verification and trust anchors")
	}
	if base.GetClientCertificate != nil {
		return nil, errors.New("strict TLS does not support dynamic client certificates")
	}
	for i := range base.Certificates {
		if err := CheckCertificate(&base.Certificates[i]); err != nil {
			return nil, fmt.Errorf("client certificate: %w", err)
		}
	}
	config := base.Clone()
	config.MinVersion = tls.VersionTLS13
	config.MaxVersion = tls.VersionTLS13
	config.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768}
	config.SessionTicketsDisabled = true
	config.ClientSessionCache = nil
	previous := config.VerifyConnection
	config.VerifyConnection = func(state tls.ConnectionState) error {
		if err := checkConnection(state); err != nil {
			return err
		}
		if len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
			return errors.New("strict TLS requires a fresh verified server certificate chain")
		}
		if err := CheckIdentity(state.VerifiedChains[0][0]); err != nil {
			return fmt.Errorf("server certificate: %w", err)
		}
		if previous != nil {
			return previous(state)
		}
		return nil
	}
	return config, nil
}
