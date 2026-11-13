/*
SPDX-License-Identifier: Apache-2.0
*/

package oqs

import (
	"bytes"
	"crypto/mldsa"
	"crypto/rand"
	"fmt"
)

type SigType string

const (
	MLDSA65ProfileV1    SigType = "ML-DSA-65-FIPS204-PURE-EMPTY-CONTEXT-v1"
	defaultProfile      SigType = "DEFAULT"
	UnknownKeyAlgorithm SigType = "UnknownKeyAlgorithm"
)

type SecretKey struct {
	Sk []byte
	PublicKey
}

type PublicKey struct {
	Pk  []byte
	Sig OQSSigInfo
}

type OQSSigInfo struct {
	Algorithm SigType
}

type OQSLib struct{}

func GetLib() (*OQSLib, error) {
	return &OQSLib{}, nil
}

func (l *OQSLib) EnabledSigs() []SigType {
	return []SigType{MLDSA65ProfileV1}
}

func normalizeProfile(profile SigType) (SigType, error) {
	if profile == "" || profile == defaultProfile {
		return MLDSA65ProfileV1, nil
	}
	if profile != MLDSA65ProfileV1 {
		return "", fmt.Errorf("unsupported post-quantum profile %q", profile)
	}
	return profile, nil
}

func requireProfile(profile SigType) error {
	if profile != MLDSA65ProfileV1 {
		return fmt.Errorf("unknown OQS algorithm name or unsupported post-quantum profile %q", profile)
	}
	return nil
}

// KeyPair creates an ML-DSA-65 key pair using the fixed versioned profile.
func KeyPair(profile SigType) (PublicKey, SecretKey, error) {
	profile, err := normalizeProfile(profile)
	if err != nil {
		return PublicKey{}, SecretKey{}, err
	}

	privateKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		return PublicKey{}, SecretKey{}, fmt.Errorf("generate %s key: %w", profile, err)
	}

	publicKey := PublicKey{
		Pk: privateKey.PublicKey().Bytes(),
		Sig: OQSSigInfo{
			Algorithm: profile,
		},
	}
	secretKey := SecretKey{
		Sk:        privateKey.Bytes(),
		PublicKey: publicKey,
	}
	return publicKey, secretKey, nil
}

// Sign signs the supplied message bytes with pure ML-DSA-65 and an empty context.
func Sign(secretKey SecretKey, message []byte) ([]byte, error) {
	if err := requireProfile(secretKey.Sig.Algorithm); err != nil {
		return nil, err
	}

	privateKey, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), secretKey.Sk)
	if err != nil {
		return nil, fmt.Errorf("decode %s private key: %w", secretKey.Sig.Algorithm, err)
	}
	if !bytes.Equal(privateKey.PublicKey().Bytes(), secretKey.Pk) {
		return nil, fmt.Errorf("%s private and public keys do not match", secretKey.Sig.Algorithm)
	}

	signature, err := privateKey.Sign(rand.Reader, message, &mldsa.Options{Context: ""})
	if err != nil {
		return nil, fmt.Errorf("sign with %s: %w", secretKey.Sig.Algorithm, err)
	}
	return signature, nil
}

// Verify verifies pure ML-DSA-65 signatures using an empty context.
func Verify(publicKey PublicKey, signature, message []byte) (bool, error) {
	if err := requireProfile(publicKey.Sig.Algorithm); err != nil {
		return false, err
	}

	key, err := mldsa.NewPublicKey(mldsa.MLDSA65(), publicKey.Pk)
	if err != nil {
		return false, fmt.Errorf("decode %s public key: %w", publicKey.Sig.Algorithm, err)
	}
	if err := mldsa.Verify(key, message, signature, &mldsa.Options{Context: ""}); err != nil {
		return false, fmt.Errorf("invalid %s signature: %w", publicKey.Sig.Algorithm, err)
	}
	return true, nil
}
