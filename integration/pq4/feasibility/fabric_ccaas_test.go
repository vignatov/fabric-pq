/*
SPDX-License-Identifier: Apache-2.0
*/

package feasibility

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/hyperledger/fabric-chaincode-go/v2/shim"
	peerproto "github.com/hyperledger/fabric-protos-go-apiv2/peer"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
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
			require.Equal(t, peerproto.ChaincodeMessage_REGISTER, message.Type)
			state := <-states
			require.Equal(t, uint16(tls.VersionTLS13), state.Version)
			require.Equal(t, test.group, state.CurveID)
			require.NotEmpty(t, state.VerifiedChains)
			require.False(t, state.DidResume)
		})
	}
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
