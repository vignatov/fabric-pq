package oqs

import (
	"crypto/mldsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWycheproofMLDSA65Vector(t *testing.T) {
	// C2SP/Wycheproof tcId 1 from commit 20b256949ea8f21a11375619b1825027ca0668bd.
	seed, err := hex.DecodeString("2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a")
	require.NoError(t, err)

	privateKey, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), seed)
	require.NoError(t, err)
	message := []byte("Hello world")

	publicKeyHash := sha256.Sum256(privateKey.PublicKey().Bytes())
	require.Equal(t, "b7acce2ddb11f8cc1aa46e2bafac6eacfa2b732ef192bd636ad8d3a56d649c66", hex.EncodeToString(publicKeyHash[:]))

	signature, err := privateKey.SignDeterministic(message, &mldsa.Options{Context: ""})
	require.NoError(t, err)
	signatureHash := sha256.Sum256(signature)
	require.Equal(t, "39fbbb0d97a52c79844213b325af823a7f16a174e00a5b3daeb3e6e6d1c89681", hex.EncodeToString(signatureHash[:]))
	require.NoError(t, mldsa.Verify(privateKey.PublicKey(), message, signature, &mldsa.Options{Context: ""}))
}

func TestMLDSA65RoundTripAndFailures(t *testing.T) {
	publicKey, secretKey, err := KeyPair(MLDSA65ProfileV1)
	require.NoError(t, err)
	require.Equal(t, MLDSA65ProfileV1, publicKey.Sig.Algorithm)
	require.Len(t, publicKey.Pk, mldsa.MLDSA65().PublicKeySize())
	require.Len(t, secretKey.Sk, mldsa.PrivateKeySize)

	message := []byte("Fabric hybrid signature input")
	signature, err := Sign(secretKey, message)
	require.NoError(t, err)
	require.Len(t, signature, mldsa.MLDSA65().SignatureSize())

	valid, err := Verify(publicKey, signature, message)
	require.NoError(t, err)
	require.True(t, valid)

	valid, err = Verify(publicKey, signature, []byte("different message"))
	require.Error(t, err)
	require.False(t, valid)

	wrongPublicKey, _, err := KeyPair(MLDSA65ProfileV1)
	require.NoError(t, err)
	valid, err = Verify(wrongPublicKey, signature, message)
	require.Error(t, err)
	require.False(t, valid)

	badSignature := append([]byte(nil), signature...)
	badSignature[0] ^= 0x01
	valid, err = Verify(publicKey, badSignature, message)
	require.Error(t, err)
	require.False(t, valid)

	secretKey.Pk = append([]byte(nil), secretKey.Pk...)
	secretKey.Pk[0] ^= 0x01
	_, err = Sign(secretKey, message)
	require.Error(t, err)
}

func TestMLDSA65RejectsMalformedAndUnsupportedInputs(t *testing.T) {
	_, secretKey, err := KeyPair(MLDSA65ProfileV1)
	require.NoError(t, err)

	_, _, err = KeyPair("Dilithium3")
	require.Error(t, err)
	_, err = Sign(SecretKey{
		Sk:       secretKey.Sk,
		PublicKey: PublicKey{Pk: secretKey.Pk, Sig: OQSSigInfo{Algorithm: "Dilithium3"}},
	}, []byte("message"))
	require.Error(t, err)
	_, err = Verify(PublicKey{Sig: OQSSigInfo{Algorithm: "Dilithium3"}}, nil, []byte("message"))
	require.Error(t, err)

	malformedPrivateKey := secretKey
	malformedPrivateKey.Sk = []byte{1, 2, 3}
	_, err = Sign(malformedPrivateKey, []byte("message"))
	require.Error(t, err)

	_, err = Verify(PublicKey{
		Pk:  []byte{1, 2, 3},
		Sig: OQSSigInfo{Algorithm: MLDSA65ProfileV1},
	}, make([]byte, mldsa.MLDSA65().SignatureSize()), []byte("message"))
	require.Error(t, err)
}

func TestMLDSA65RFC9881KeyEncoding(t *testing.T) {
	publicKey, secretKey, err := KeyPair(MLDSA65ProfileV1)
	require.NoError(t, err)

	publicDER, err := MarshalPKIXPublicKey(&publicKey)
	require.NoError(t, err)
	var publicInfo struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	rest, err := asn1.Unmarshal(publicDER, &publicInfo)
	require.NoError(t, err)
	require.Empty(t, rest)
	require.Equal(t, oidMLDSA65, publicInfo.Algorithm.Algorithm)
	require.Empty(t, publicInfo.Algorithm.Parameters.FullBytes)
	require.Equal(t, publicKey.Pk, publicInfo.PublicKey.RightAlign())

	parsedPublic, err := x509.ParsePKIXPublicKey(publicDER)
	require.NoError(t, err)
	require.IsType(t, &mldsa.PublicKey{}, parsedPublic)

	nullParametersDER, err := asn1.Marshal(struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm:  oidMLDSA65,
			Parameters: asn1.NullRawValue,
		},
		PublicKey: publicInfo.PublicKey,
	})
	require.NoError(t, err)
	_, err = ParsePKIXPublicKey(nullParametersDER)
	require.Error(t, err)

	unalignedPublicDER, err := asn1.Marshal(struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm: oidMLDSA65,
		},
		PublicKey: asn1.BitString{
			Bytes:     publicKey.Pk,
			BitLength: len(publicKey.Pk)*8 - 1,
		},
	})
	require.NoError(t, err)
	_, err = ParsePKIXPublicKey(unalignedPublicDER)
	require.Error(t, err)

	unsupportedOIDDER, err := asn1.Marshal(struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 40},
		},
		PublicKey: publicInfo.PublicKey,
	})
	require.NoError(t, err)
	_, err = ParsePKIXPublicKey(unsupportedOIDDER)
	require.Error(t, err)

	privateDER, err := MarshalPKIXPrivateKey(&secretKey)
	require.NoError(t, err)
	var privateInfo struct {
		Version    int
		Algorithm  pkix.AlgorithmIdentifier
		PrivateKey []byte
	}
	rest, err = asn1.Unmarshal(privateDER, &privateInfo)
	require.NoError(t, err)
	require.Empty(t, rest)
	require.Equal(t, oidMLDSA65, privateInfo.Algorithm.Algorithm)
	require.Empty(t, privateInfo.Algorithm.Parameters.FullBytes)

	parsedPrivate, err := x509.ParsePKCS8PrivateKey(privateDER)
	require.NoError(t, err)
	require.IsType(t, &mldsa.PrivateKey{}, parsedPrivate)

	roundTripped, err := ParsePKIXPrivateKey(privateDER)
	require.NoError(t, err)
	require.Equal(t, secretKey.Sk, roundTripped.(*SecretKey).Sk)
}

func TestParsePKIXPrivateKeyRejectsOtherMLDSAParameterSets(t *testing.T) {
	for _, parameters := range []mldsa.Parameters{mldsa.MLDSA44(), mldsa.MLDSA87()} {
		t.Run(parameters.String(), func(t *testing.T) {
			privateKey, err := mldsa.GenerateKey(parameters)
			require.NoError(t, err)

			der, err := x509.MarshalPKCS8PrivateKey(privateKey)
			require.NoError(t, err)

			_, err = ParsePKIXPrivateKey(der)
			require.Error(t, err)
			require.Contains(t, err.Error(), "only ML-DSA-65 is supported")
		})
	}
}
