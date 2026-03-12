/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sw

import (
	"crypto/sha256"
	"errors"

	"github.com/hyperledger/fabric-lib-go/bccsp"
	oqspkg "github.com/hyperledger/fabric/pq-crypto"
)

// oqsPrivateKey implements a bccsp.Key interface.
type oqsPrivateKey struct {
	privKey *oqspkg.SecretKey
}

// Bytes converts this key to its byte representation, if this operation is allowed.
func (k *oqsPrivateKey) Bytes() ([]byte, error) {
	return nil, errors.New("not supported")
}

// SKI returns the subject key identifier of this key.
func (k *oqsPrivateKey) SKI() []byte {
	if k.privKey == nil {
		return nil
	}
	algBytes := []byte(k.privKey.Sig.Algorithm)

	hash := sha256.New()
	hash.Write(append(k.privKey.Pk, algBytes...))
	return hash.Sum(nil)
}

func (k *oqsPrivateKey) Symmetric() bool {
	return false
}

func (k *oqsPrivateKey) Private() bool {
	return true
}

func (k *oqsPrivateKey) PublicKey() (bccsp.Key, error) {
	return &oqsPublicKey{pubKey: &k.privKey.PublicKey}, nil
}

// oqsPublicKey implements a bccsp.Key interface.
type oqsPublicKey struct {
	pubKey *oqspkg.PublicKey
}

func (k *oqsPublicKey) Bytes() ([]byte, error) {
	if k.pubKey == nil {
		return nil, nil
	}
	return oqspkg.MarshalPKIXPublicKey(k.pubKey)
}

// SKI returns the subject key identifier of this key.
func (k *oqsPublicKey) SKI() []byte {
	if k.pubKey == nil {
		return nil
	}
	algBytes := []byte(k.pubKey.Sig.Algorithm)

	hash := sha256.New()
	hash.Write(append(k.pubKey.Pk, algBytes...))
	return hash.Sum(nil)
}

func (k *oqsPublicKey) Symmetric() bool {
	return false
}

func (k *oqsPublicKey) Private() bool {
	return false
}

func (k *oqsPublicKey) PublicKey() (bccsp.Key, error) {
	return k, nil
}
