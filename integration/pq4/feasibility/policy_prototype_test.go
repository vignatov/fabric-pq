/*
SPDX-License-Identifier: Apache-2.0
*/

package feasibility

import (
	"bytes"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hyperledger/fabric-lib-go/bccsp/sw"
	commonproto "github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric/common/channelconfig"
	configtxtest "github.com/hyperledger/fabric/common/configtx/test"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

type prototypePolicy struct {
	Network  string            `json:"network"`
	Node     string            `json:"node"`
	Version  uint64            `json:"version"`
	Profile  string            `json:"profile"`
	Channels map[string]string `json:"channels"`
}

type prototypeCheckpoint struct {
	version uint64
	digest  [32]byte
}

const prototypeStrictProfile = "experimental-tls13-x25519mlkem768-mldsa65"

func bootstrapPrototypePolicy(
	payload, signature []byte,
	signer *mldsa.PublicKey,
	checkpoint *prototypeCheckpoint,
	network, node string,
	base *tls.Config,
) (prototypePolicy, *tls.Config, error) {
	var policy prototypePolicy
	if len(payload) == 0 || len(signature) == 0 || signer == nil || checkpoint == nil || base == nil || network == "" || node == "" {
		return policy, nil, errors.New("missing policy, trust anchor, checkpoint, bootstrap identity, or TLS configuration")
	}
	if err := mldsa.Verify(signer, payload, signature, nil); err != nil {
		return policy, nil, fmt.Errorf("policy signature verification: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&policy); err != nil {
		return policy, nil, fmt.Errorf("decode policy: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return policy, nil, errors.New("policy contains trailing data")
	}
	if policy.Version != checkpoint.version {
		return policy, nil, errors.New("policy version conflicts with trusted checkpoint")
	}
	if sha256.Sum256(payload) != checkpoint.digest {
		return policy, nil, errors.New("policy digest conflicts with trusted checkpoint")
	}
	if policy.Network != network || policy.Node != node {
		return policy, nil, errors.New("policy network or node conflicts with bootstrap identity")
	}
	if policy.Profile != prototypeStrictProfile {
		return policy, nil, errors.New("policy attempts to weaken the strict profile")
	}
	if len(policy.Channels) == 0 {
		return policy, nil, errors.New("policy has no channel bindings")
	}
	if base.ClientCAs == nil || len(base.Certificates) == 0 || base.VerifyConnection != nil {
		return policy, nil, errors.New("incomplete or incompatible server TLS configuration")
	}
	if len(base.Certificates[0].Certificate) == 0 {
		return policy, nil, errors.New("missing server identity")
	}
	serverCert, err := x509.ParseCertificate(base.Certificates[0].Certificate[0])
	if err != nil {
		return policy, nil, fmt.Errorf("parse server identity: %w", err)
	}
	serverKey, ok := serverCert.PublicKey.(*mldsa.PublicKey)
	if !ok || serverKey.Parameters() != mldsa.MLDSA65() || serverCert.SignatureAlgorithm != x509.MLDSA65 {
		return policy, nil, errors.New("server identity is not ML-DSA-65")
	}

	config := base.Clone()
	config.MinVersion = tls.VersionTLS13
	config.MaxVersion = tls.VersionTLS13
	config.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768}
	config.ClientAuth = tls.RequireAndVerifyClientCert
	config.SessionTicketsDisabled = true
	config.VerifyConnection = func(state tls.ConnectionState) error {
		if state.DidResume || len(state.VerifiedChains) == 0 {
			return errors.New("missing fresh verified client certificate chain")
		}
		for _, cert := range state.VerifiedChains[0] {
			key, ok := cert.PublicKey.(*mldsa.PublicKey)
			if !ok || key.Parameters() != mldsa.MLDSA65() || cert.SignatureAlgorithm != x509.MLDSA65 {
				return errors.New("client certificate chain is not ML-DSA-65")
			}
		}
		return nil
	}
	return policy, config, nil
}

func authorizePrototypeChannel(policy prototypePolicy, channel string, config *commonproto.Config) error {
	expected, ok := policy.Channels[channel]
	if !ok || config == nil {
		return errors.New("channel is not bound to the policy")
	}
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(config)
	if err != nil {
		return fmt.Errorf("marshal channel configuration: %w", err)
	}
	digest := sha256.Sum256(encoded)
	if expected != hex.EncodeToString(digest[:]) {
		return errors.New("channel configuration conflicts with the policy")
	}
	return nil
}

func signPrototypePolicy(t *testing.T, signer *mldsa.PrivateKey, policy prototypePolicy) ([]byte, []byte, prototypeCheckpoint) {
	t.Helper()
	payload, err := json.Marshal(policy)
	require.NoError(t, err)
	signature, err := signer.Sign(rand.Reader, payload, nil)
	require.NoError(t, err)
	return payload, signature, prototypeCheckpoint{version: policy.Version, digest: sha256.Sum256(payload)}
}

func TestAuthenticatedPolicyPrototype(t *testing.T) {
	signer, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	public, ok := signer.Public().(*mldsa.PublicKey)
	require.True(t, ok)
	otherSigner, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	otherPublic, ok := otherSigner.Public().(*mldsa.PublicKey)
	require.True(t, ok)

	channelConfig, err := configtxtest.MakeChannelConfig("channel-a")
	require.NoError(t, err)
	provider, err := sw.NewDefaultSecurityLevelWithKeystore(sw.NewDummyKeyStore())
	require.NoError(t, err)
	_, err = channelconfig.NewBundle("channel-a", channelConfig, provider)
	require.NoError(t, err)
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(channelConfig)
	require.NoError(t, err)
	channelDigest := sha256.Sum256(encoded)
	original := prototypePolicy{
		Network: "network-a", Node: "peer-a", Version: 2, Profile: prototypeStrictProfile,
		Channels: map[string]string{"channel-a": hex.EncodeToString(channelDigest[:])},
	}
	payload, signature, checkpoint := signPrototypePolicy(t, signer, original)
	ca := newAuthority(t)
	server := ca.leaf(t, x509.ExtKeyUsageServerAuth, false)
	client := ca.leaf(t, x509.ExtKeyUsageClientAuth, false)
	serverBase, clientConfig := configs(ca, server, client, true)

	policy, serverConfig, err := bootstrapPrototypePolicy(payload, signature, public, &checkpoint, "network-a", "peer-a", serverBase)
	require.NoError(t, err)
	require.NoError(t, authorizePrototypeChannel(policy, "channel-a", channelConfig))
	require.ErrorContains(t, authorizePrototypeChannel(policy, "channel-b", channelConfig), "not bound")
	changedConfig := proto.Clone(channelConfig).(*commonproto.Config)
	changedConfig.Sequence++
	require.ErrorContains(t, authorizePrototypeChannel(policy, "channel-a", changedConfig), "conflicts")

	serverResult, clientResult := exchange(t, serverConfig, clientConfig)
	require.NoError(t, serverResult.err)
	require.NoError(t, clientResult.err)
	assertStrictState(t, serverResult.state, true)
	assertStrictState(t, clientResult.state, true)

	classicalKEM := clientConfig.Clone()
	classicalKEM.CurvePreferences = []tls.CurveID{tls.X25519}
	serverResult, clientResult = exchange(t, serverConfig, classicalKEM)
	require.Error(t, serverResult.err)
	require.Error(t, clientResult.err)
	require.Contains(t, fmt.Sprintf("%v %v", serverResult.err, clientResult.err), "key exchange")

	oldTLS := clientConfig.Clone()
	oldTLS.MinVersion, oldTLS.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
	serverResult, clientResult = exchange(t, serverConfig, oldTLS)
	require.Error(t, serverResult.err)
	require.Error(t, clientResult.err)
	require.Contains(t, fmt.Sprintf("%v %v", serverResult.err, clientResult.err), "unsupported versions")

	classicalIdentity := clientConfig.Clone()
	classicalIdentity.Certificates = []tls.Certificate{ca.classicalLeaf(t, x509.ExtKeyUsageClientAuth)}
	serverResult, clientResult = exchange(t, serverConfig, classicalIdentity)
	require.Error(t, serverResult.err)
	require.Error(t, clientResult.err)
	require.Contains(t, fmt.Sprintf("%v %v", serverResult.err, clientResult.err), "client certificate chain is not ML-DSA-65")

	t.Run("bootstrap rejection", func(t *testing.T) {
		tampered := append([]byte(nil), payload...)
		tampered[0] ^= 1
		stale := original
		stale.Version--
		stalePayload, staleSignature, staleCheckpoint := signPrototypePolicy(t, signer, stale)
		conflict := original
		conflict.Node = "other-node"
		conflictPayload, conflictSignature, _ := signPrototypePolicy(t, signer, conflict)
		weak := original
		weak.Version++
		weak.Profile = "classical"
		weakPayload, weakSignature, weakCheckpoint := signPrototypePolicy(t, signer, weak)

		for _, test := range []struct {
			name       string
			payload    []byte
			signature  []byte
			signer     *mldsa.PublicKey
			checkpoint *prototypeCheckpoint
			network    string
			cause      string
		}{
			{"missing policy", nil, signature, public, &checkpoint, "network-a", "missing policy"},
			{"missing checkpoint", payload, signature, public, nil, "network-a", "missing policy"},
			{"untrusted signer", payload, signature, otherPublic, &checkpoint, "network-a", "signature verification"},
			{"tampered payload", tampered, signature, public, &checkpoint, "network-a", "signature verification"},
			{"stale signed policy", stalePayload, staleSignature, public, &checkpoint, "network-a", "version conflicts"},
			{"same-version equivocation", conflictPayload, conflictSignature, public, &checkpoint, "network-a", "digest conflicts"},
			{"wrong network", payload, signature, public, &checkpoint, "network-b", "conflicts with bootstrap identity"},
			{"authorized weaker profile", weakPayload, weakSignature, public, &weakCheckpoint, "network-a", "weaken the strict profile"},
		} {
			t.Run(test.name, func(t *testing.T) {
				_, config, err := bootstrapPrototypePolicy(test.payload, test.signature, test.signer, test.checkpoint, test.network, "peer-a", serverBase)
				require.ErrorContains(t, err, test.cause)
				require.Nil(t, config)
			})
		}

		restored, config, err := bootstrapPrototypePolicy(stalePayload, staleSignature, public, &staleCheckpoint, "network-a", "peer-a", serverBase)
		require.NoError(t, err)
		require.NotNil(t, config)
		require.Equal(t, stale.Version, restored.Version)

		_, config, err = bootstrapPrototypePolicy(payload, signature, public, &checkpoint, "network-a", "other-node", serverBase)
		require.ErrorContains(t, err, "conflicts with bootstrap identity")
		require.Nil(t, config)

		classicalServer := serverBase.Clone()
		classicalServer.Certificates = []tls.Certificate{ca.classicalLeaf(t, x509.ExtKeyUsageServerAuth)}
		_, config, err = bootstrapPrototypePolicy(payload, signature, public, &checkpoint, "network-a", "peer-a", classicalServer)
		require.ErrorContains(t, err, "server identity is not ML-DSA-65")
		require.Nil(t, config)
	})

	t.Run("separately stored policy witness", func(t *testing.T) {
		authorityDir := t.TempDir()
		nodeDir := t.TempDir()
		authorityPath := filepath.Join(authorityDir, "policy.json")
		nodePolicyPath := filepath.Join(nodeDir, "policy.json")
		nodeSignaturePath := filepath.Join(nodeDir, "policy.sig")
		require.NoError(t, os.WriteFile(authorityPath, payload, 0o600))
		require.NoError(t, os.WriteFile(nodePolicyPath, payload, 0o600))
		require.NoError(t, os.WriteFile(nodeSignaturePath, signature, 0o600))

		witnessCert := ca.leaf(t, x509.ExtKeyUsageServerAuth, false)
		nodeCert := ca.leaf(t, x509.ExtKeyUsageClientAuth, false)
		witnessTLS, nodeTLS := configs(ca, witnessCert, nodeCert, true)
		serverStates := make(chan tls.ConnectionState, 1)
		fileServer := http.FileServer(http.Dir(authorityDir))
		witness := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			serverStates <- *r.TLS
			fileServer.ServeHTTP(w, r)
		}))
		witness.TLS = witnessTLS
		witness.StartTLS()
		t.Cleanup(witness.Close)
		transport := &http.Transport{TLSClientConfig: nodeTLS, DisableKeepAlives: true}
		t.Cleanup(transport.CloseIdleConnections)
		httpClient := &http.Client{Transport: transport, Timeout: 5 * time.Second}
		fetchCheckpoint := func() (prototypeCheckpoint, error) {
			response, err := httpClient.Get(witness.URL + "/policy.json")
			if err != nil {
				return prototypeCheckpoint{}, err
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusOK {
				return prototypeCheckpoint{}, fmt.Errorf("witness returned HTTP %d", response.StatusCode)
			}
			remotePayload, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
			if err != nil {
				return prototypeCheckpoint{}, err
			}
			if len(remotePayload) > 1<<20 {
				return prototypeCheckpoint{}, errors.New("witness policy exceeds size limit")
			}
			var remotePolicy prototypePolicy
			if err := json.Unmarshal(remotePayload, &remotePolicy); err != nil {
				return prototypeCheckpoint{}, fmt.Errorf("decode witness policy: %w", err)
			}
			assertStrictState(t, *response.TLS, true)
			assertStrictState(t, <-serverStates, true)
			return prototypeCheckpoint{version: remotePolicy.Version, digest: sha256.Sum256(remotePayload)}, nil
		}
		bootstrapFromDisk := func(cp *prototypeCheckpoint) (*tls.Config, error) {
			localPayload, err := os.ReadFile(nodePolicyPath)
			if err != nil {
				return nil, err
			}
			localSignature, err := os.ReadFile(nodeSignaturePath)
			if err != nil {
				return nil, err
			}
			_, config, err := bootstrapPrototypePolicy(localPayload, localSignature, public, cp, "network-a", "peer-a", serverBase)
			return config, err
		}

		fresh, err := fetchCheckpoint()
		require.NoError(t, err)
		config, err := bootstrapFromDisk(&fresh)
		require.NoError(t, err)
		require.NotNil(t, config)

		untrustedTLS := nodeTLS.Clone()
		untrustedTLS.RootCAs = newAuthority(t).pool
		untrustedTransport := &http.Transport{TLSClientConfig: untrustedTLS, DisableKeepAlives: true}
		defer untrustedTransport.CloseIdleConnections()
		untrustedClient := &http.Client{Transport: untrustedTransport, Timeout: 5 * time.Second}
		response, err := untrustedClient.Get(witness.URL + "/policy.json")
		if response != nil {
			require.NoError(t, response.Body.Close())
		}
		require.ErrorContains(t, err, "certificate signed by unknown authority")

		missingClientTLS := nodeTLS.Clone()
		missingClientTLS.Certificates = nil
		missingClientTransport := &http.Transport{TLSClientConfig: missingClientTLS, DisableKeepAlives: true}
		defer missingClientTransport.CloseIdleConnections()
		missingClient := &http.Client{Transport: missingClientTransport, Timeout: 5 * time.Second}
		response, err = missingClient.Get(witness.URL + "/policy.json")
		if response != nil {
			require.NoError(t, response.Body.Close())
		}
		require.ErrorContains(t, err, "certificate required")

		stale := original
		stale.Version--
		stalePayload, staleSignature, _ := signPrototypePolicy(t, signer, stale)
		require.NoError(t, os.WriteFile(nodePolicyPath, stalePayload, 0o600))
		require.NoError(t, os.WriteFile(nodeSignaturePath, staleSignature, 0o600))
		fresh, err = fetchCheckpoint()
		require.NoError(t, err)
		config, err = bootstrapFromDisk(&fresh)
		require.ErrorContains(t, err, "version conflicts")
		require.Nil(t, config)

		require.NoError(t, os.WriteFile(authorityPath, stalePayload, 0o600))
		restored, err := fetchCheckpoint()
		require.NoError(t, err)
		config, err = bootstrapFromDisk(&restored)
		require.NoError(t, err)
		require.NotNil(t, config)

		witness.Close()
		_, err = fetchCheckpoint()
		require.Error(t, err)
		config, err = bootstrapFromDisk(nil)
		require.ErrorContains(t, err, "missing policy")
		require.Nil(t, config)
	})
}
