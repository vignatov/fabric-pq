/*
SPDX-License-Identifier: Apache-2.0
*/

package feasibility

import (
	"bytes"
	"context"
	"crypto/mldsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/hyperledger/fabric-chaincode-go/v2/shim"
	peerproto "github.com/hyperledger/fabric-protos-go-apiv2/peer"
	"github.com/hyperledger/fabric/core/chaincode/extcc"
	"github.com/hyperledger/fabric/core/container/ccintf"
	"github.com/hyperledger/fabric/core/container/externalbuilder"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/proto"
)

type feasibilityChaincode struct{}

func (feasibilityChaincode) Init(shim.ChaincodeStubInterface) *peerproto.Response {
	return &peerproto.Response{}
}

func (feasibilityChaincode) Invoke(shim.ChaincodeStubInterface) *peerproto.Response {
	return &peerproto.Response{}
}

type chaincodeServerInput struct {
	Address string
	Key     []byte
	Cert    []byte
	CA      []byte
}

type registrationHandler struct{ chaincodeID string }

// This guard only rejects plaintext metadata; it is not complete strict TLS policy validation.
func rejectPlaintextCCAASMetadata(metadata externalbuilder.ChaincodeServerUserData) error {
	if metadata.TLSRequired {
		return nil
	}
	return errors.New("strict PQ4 policy rejects plaintext CCAAS metadata")
}

func (handler registrationHandler) HandleChaincodeStream(stream ccintf.ChaincodeStream) error {
	message, err := stream.Recv()
	if err != nil {
		return err
	}
	if message.GetType() != peerproto.ChaincodeMessage_REGISTER {
		return errors.New("expected chaincode registration")
	}
	id := &peerproto.ChaincodeID{}
	if err := proto.Unmarshal(message.GetPayload(), id); err != nil {
		return err
	}
	if id.GetName() != handler.chaincodeID {
		return errors.New("unexpected registered chaincode ID")
	}
	return nil
}

type plaintextRegistrationServer struct {
	peerproto.UnimplementedChaincodeServer
	authInfo chan credentials.AuthInfo
}

func (server *plaintextRegistrationServer) Connect(stream peerproto.Chaincode_ConnectServer) error {
	remote, ok := peer.FromContext(stream.Context())
	if !ok {
		return errors.New("missing external chaincode client peer")
	}
	server.authInfo <- remote.AuthInfo
	payload, err := proto.Marshal(&peerproto.ChaincodeID{Name: "pq4-feasibility"})
	if err != nil {
		return err
	}
	return stream.Send(&peerproto.ChaincodeMessage{Type: peerproto.ChaincodeMessage_REGISTER, Payload: payload})
}

func TestFabricCCAASPlaintextMetadata(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := grpc.NewServer()
	fixture := &plaintextRegistrationServer{authInfo: make(chan credentials.AuthInfo, 1)}
	peerproto.RegisterChaincodeServer(server, fixture)
	serveErrors := make(chan error, 1)
	go func() { serveErrors <- server.Serve(listener) }()
	defer func() {
		server.Stop()
		require.NoError(t, <-serveErrors)
	}()

	for _, test := range []struct {
		name               string
		clientAuthRequired bool
	}{
		{"plaintext metadata", false},
		{"plaintext metadata with client auth requested", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			releaseDir := t.TempDir()
			instance := &externalbuilder.Instance{ReleaseDir: releaseDir}
			require.NoError(t, os.MkdirAll(instance.ChaincodeServerReleaseDir(), 0o700))
			metadata, err := json.Marshal(externalbuilder.ChaincodeServerUserData{
				Address:            listener.Addr().String(),
				TLSRequired:        false,
				ClientAuthRequired: test.clientAuthRequired,
			})
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(filepath.Join(instance.ChaincodeServerReleaseDir(), "connection.json"), metadata, 0o600))
			info, err := instance.ChaincodeServerInfo()
			require.NoError(t, err)
			require.NotNil(t, info)
			require.False(t, info.ClientConfig.SecOpts.UseTLS)
			info.ClientConfig.DialTimeout = 5 * time.Second
			result := make(chan error, 1)
			go func() {
				result <- (&extcc.ExternalChaincodeRuntime{}).Stream(
					"pq4-feasibility", info, registrationHandler{chaincodeID: "pq4-feasibility"},
				)
			}()
			select {
			case err := <-result:
				require.NoError(t, err)
			case <-time.After(15 * time.Second):
				t.Fatal("external chaincode registration timed out")
			}
			select {
			case auth := <-fixture.authInfo:
				require.Nil(t, auth, "plaintext gRPC connection unexpectedly had authentication information")
			default:
				t.Fatal("chaincode server did not observe the peer")
			}
		})
	}

	t.Run("strict PQ4 rejects plaintext metadata", func(t *testing.T) {
		require.ErrorContains(t, rejectPlaintextCCAASMetadata(externalbuilder.ChaincodeServerUserData{
			TLSRequired: false,
		}), "rejects plaintext")
		require.ErrorContains(t, rejectPlaintextCCAASMetadata(externalbuilder.ChaincodeServerUserData{
			TLSRequired:        false,
			ClientAuthRequired: true,
		}), "rejects plaintext")
		require.NoError(t, rejectPlaintextCCAASMetadata(externalbuilder.ChaincodeServerUserData{
			TLSRequired:        true,
			ClientAuthRequired: true,
		}))
	})
}

func TestFabricCCAASShimMLDSACompatibility(t *testing.T) {
	if os.Getenv("FABRIC_PQ4_SHIM_FEASIBILITY_HELPER") == "1" {
		runChaincodeServerHelper(t)
		return
	}

	ca := newAuthority(t)
	serverCert := ca.leaf(t, x509.ExtKeyUsageServerAuth, false)
	clientCert := ca.leaf(t, x509.ExtKeyUsageClientAuth, false)
	serverPEM, serverKey := pemPair(t, serverCert)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().String()
	require.NoError(t, listener.Close())

	command := exec.Command(os.Args[0], "-test.run=^TestFabricCCAASShimMLDSACompatibility$")
	command.Env = append(os.Environ(), "FABRIC_PQ4_SHIM_FEASIBILITY_HELPER=1")
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	input, err := command.StdinPipe()
	require.NoError(t, err)
	require.NoError(t, command.Start())
	t.Cleanup(func() {
		closeErr := input.Close()
		waitErr := command.Wait()
		require.NoError(t, closeErr)
		require.NoError(t, waitErr, output.String())
	})
	require.NoError(t, json.NewEncoder(input).Encode(chaincodeServerInput{
		Address: address, Key: serverKey, Cert: serverPEM, CA: caPEM,
	}))

	for _, test := range []struct {
		name  string
		group tls.CurveID
	}{
		{"hybrid client", tls.X25519MLKEM768},
		{"classical-only client", tls.X25519},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, clientConfig := configs(ca, serverCert, clientCert, true)
			clientConfig.CurvePreferences = []tls.CurveID{test.group}
			states := make(chan tls.ConnectionState, 1)
			clientConfig.VerifyConnection = func(state tls.ConnectionState) error {
				select {
				case states <- state:
					return nil
				default:
					return errors.New("unexpected repeated CCAAS TLS handshake")
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			conn, err := grpc.DialContext(ctx, address, grpc.WithBlock(),
				grpc.WithTransportCredentials(credentials.NewTLS(clientConfig)))
			require.NoError(t, err)
			defer conn.Close()
			stream, err := peerproto.NewChaincodeClient(conn).Connect(ctx)
			require.NoError(t, err)
			message, err := stream.Recv()
			require.NoError(t, err)
			require.Equal(t, peerproto.ChaincodeMessage_REGISTER, message.GetType())
			state := <-states
			require.Equal(t, uint16(tls.VersionTLS13), state.Version)
			require.Equal(t, test.group, state.CurveID)
			require.NotEmpty(t, state.VerifiedChains)
			require.False(t, state.DidResume)
		})
	}

	t.Run("Fabric external chaincode client", func(t *testing.T) {
		clientPEM, clientKey := pemPair(t, clientCert)
		userData := &externalbuilder.ChaincodeServerUserData{
			Address:            address,
			Domain:             "pq4.example",
			TLSRequired:        true,
			ClientAuthRequired: true,
			ClientKey:          string(clientKey),
			ClientCert:         string(clientPEM),
			RootCert:           string(caPEM),
		}
		info, err := userData.ChaincodeServerInfo("")
		require.NoError(t, err)
		require.NotNil(t, info)
		info.ClientConfig.DialTimeout = 5 * time.Second
		verified := make(chan *x509.Certificate, 1)
		info.ClientConfig.SecOpts.VerifyCertificate = func(_ [][]byte, chains [][]*x509.Certificate) error {
			if len(chains) == 0 || len(chains[0]) == 0 {
				return errors.New("missing verified CCAAS server chain")
			}
			select {
			case verified <- chains[0][0]:
				return nil
			default:
				return errors.New("unexpected repeated CCAAS TLS handshake")
			}
		}
		result := make(chan error, 1)
		go func() {
			result <- (&extcc.ExternalChaincodeRuntime{}).Stream(
				"pq4-feasibility", info, registrationHandler{chaincodeID: "pq4-feasibility"},
			)
		}()
		select {
		case err := <-result:
			require.NoError(t, err)
		case <-time.After(15 * time.Second):
			t.Fatal("external chaincode registration timed out")
		}
		var serverIdentity *x509.Certificate
		select {
		case serverIdentity = <-verified:
		default:
			t.Fatal("external client did not report a verified server chain")
		}
		key, ok := serverIdentity.PublicKey.(*mldsa.PublicKey)
		require.True(t, ok)
		require.Equal(t, mldsa.MLDSA65(), key.Parameters())
		require.Equal(t, x509.MLDSA65, serverIdentity.SignatureAlgorithm)
	})
}

func runChaincodeServerHelper(t *testing.T) {
	var input chaincodeServerInput
	require.NoError(t, json.NewDecoder(os.Stdin).Decode(&input))
	server := &shim.ChaincodeServer{
		CCID:    "pq4-feasibility",
		Address: input.Address,
		CC:      feasibilityChaincode{},
		TLSProps: shim.TLSProperties{
			Key: input.Key, Cert: input.Cert, ClientCACerts: input.CA,
		},
	}
	serverResult := make(chan error, 1)
	go func() { serverResult <- server.Start() }()
	inputResult := make(chan error, 1)
	go func() {
		_, err := io.Copy(io.Discard, os.Stdin)
		inputResult <- err
	}()
	select {
	case err := <-serverResult:
		require.NoError(t, err)
		t.Fatal("chaincode server stopped unexpectedly")
	case err := <-inputResult:
		require.NoError(t, err)
	}
}
