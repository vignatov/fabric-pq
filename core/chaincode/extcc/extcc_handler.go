/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package extcc

import (
	"context"
	"sync"

	"github.com/hyperledger/fabric-lib-go/common/flogging"
	pb "github.com/hyperledger/fabric-protos-go-apiv2/peer"
	"github.com/hyperledger/fabric/core/container/ccintf"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
)

var extccLogger = flogging.MustGetLogger("extcc")

// StreamHandler handles the `Chaincode` gRPC service with peer as client
type StreamHandler interface {
	HandleChaincodeStream(stream ccintf.ChaincodeStream) error
}

type ExternalChaincodeRuntime struct {
	TransportPolicy *pqtransport.Policy
}

type externalStream struct {
	pb.Chaincode_ConnectClient
	abort func()
}

func (s *externalStream) Abort() { s.abort() }

// createConnection - standard grpc client creating using ClientConfig info (surprised there isn't
// a helper method for this)
func (i *ExternalChaincodeRuntime) createConnection(ccid string, ccinfo *ccintf.ChaincodeServerInfo) (*grpc.ClientConn, error) {
	config := ccinfo.ClientConfig
	if i.TransportPolicy != nil {
		if !config.SecOpts.UseTLS || !config.SecOpts.RequireClientCert {
			return nil, errors.New("protected external chaincode requires mutual TLS")
		}
		config.SecOpts.TransportPolicy = i.TransportPolicy
	}
	conn, err := config.Dial(ccinfo.Address)
	if err != nil {
		return nil, errors.WithMessagef(err, "error creating grpc connection to %s", ccinfo.Address)
	}

	extccLogger.Debugf("Created external chaincode connection: %s", ccid)

	return conn, nil
}

func (i *ExternalChaincodeRuntime) Stream(ccid string, ccinfo *ccintf.ChaincodeServerInfo, sHandler StreamHandler) error {
	extccLogger.Debugf("Starting external chaincode connection: %s", ccid)
	conn, err := i.createConnection(ccid, ccinfo)
	if err != nil {
		return errors.WithMessagef(err, "error cannot create connection for %s", ccid)
	}

	closeConnection := sync.OnceFunc(func() { _ = conn.Close() })
	defer closeConnection()

	// create the client and start streaming
	client := pb.NewChaincodeClient(conn)

	stream, err := client.Connect(context.Background())
	if err != nil {
		return errors.WithMessagef(err, "error creating grpc client connection to %s", ccid)
	}

	// peer as client has to initiate the stream. Rest of the process is unchanged
	if err := sHandler.HandleChaincodeStream(&externalStream{Chaincode_ConnectClient: stream, abort: closeConnection}); err != nil {
		return errors.WithMessagef(err, "error handling chaincode stream for %s", ccid)
	}

	extccLogger.Debugf("External chaincode %s client exited", ccid)

	return nil
}
