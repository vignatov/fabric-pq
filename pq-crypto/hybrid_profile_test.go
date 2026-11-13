package oqs

import (
	"crypto"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

type recordingSigner struct {
	message []byte
}

func (s *recordingSigner) Sign(_ io.Reader, message []byte, _ crypto.SignerOpts) ([]byte, error) {
	s.message = append([]byte(nil), message...)
	return []byte{0x5a}, nil
}

func (s *recordingSigner) Public() crypto.PublicKey {
	return nil
}

func TestHybridAltSignatureInputFixture(t *testing.T) {
	classicalKey := []byte{0x01, 0x02}
	quantumKey := []byte{0xa0, 0xb0}
	want := []byte{
		0x30, 0x0a,
		0x03, 0x03, 0x00, 0x01, 0x02,
		0x03, 0x03, 0x00, 0xa0, 0xb0,
	}
	signer := &recordingSigner{}

	extension, err := buildAltSignatureValueExt(quantumKey, classicalKey, signer)
	require.NoError(t, err)
	require.True(t, extension.Id.Equal(oidAltSignatureValue))
	require.Equal(t, []byte{0x5a}, extension.Value)
	require.Equal(t, want, signer.message)
}
