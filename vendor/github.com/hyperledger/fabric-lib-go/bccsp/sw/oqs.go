/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sw

import (
	"github.com/hyperledger/fabric-lib-go/bccsp"
	oqspkg "github.com/hyperledger/fabric/pq-crypto"
)

func signOQS(k *oqspkg.SecretKey, digest []byte, opts bccsp.SignerOpts) ([]byte, error) {
	return oqspkg.Sign(*k, digest)
}

func verifyOQS(k *oqspkg.PublicKey, signature, digest []byte, opts bccsp.SignerOpts) (bool, error) {
	return oqspkg.Verify(*k, signature, digest)
}

type oqsSigner struct{}

func (s *oqsSigner) Sign(k bccsp.Key, digest []byte, opts bccsp.SignerOpts) ([]byte, error) {
	return signOQS(k.(*oqsPrivateKey).privKey, digest, opts)
}

type oqsPrivateKeyVerifier struct{}

func (v *oqsPrivateKeyVerifier) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (bool, error) {
	return verifyOQS(&(k.(*oqsPrivateKey).privKey.PublicKey), signature, digest, opts)
}

type oqsPublicKeyKeyVerifier struct{}

func (v *oqsPublicKeyKeyVerifier) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (bool, error) {
	return verifyOQS(k.(*oqsPublicKey).pubKey, signature, digest, opts)
}
