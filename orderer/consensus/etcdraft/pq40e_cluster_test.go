/*
SPDX-License-Identifier: Apache-2.0
*/

package etcdraft

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/hyperledger/fabric-lib-go/common/flogging"
	"github.com/hyperledger/fabric-lib-go/common/metrics"
	"github.com/hyperledger/fabric-lib-go/common/metrics/disabled"
	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	ab "github.com/hyperledger/fabric-protos-go-apiv2/orderer"
	"github.com/hyperledger/fabric/common/crypto/tlsgen"
	"github.com/hyperledger/fabric/internal/pkg/comm"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation/testfixture"
	"github.com/hyperledger/fabric/orderer/common/cluster"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type pq40eClusterReceivers map[string]MessageReceiver

func (r pq40eClusterReceivers) ReceiverByChain(id string) MessageReceiver { return r[id] }

func TestPQ40EMixedClusterSubmitAndRestart(t *testing.T) {
	const baseline = "baseline"
	fixture := testfixture.New(t)
	genesis := testfixture.Genesis(t)
	dir := t.TempDir()
	store, err := activation.OpenStore(dir, nil)
	require.NoError(t, err)
	fixture.Provision(t, store, testfixture.Config(t, genesis))
	recoverChannel := func() (*activation.Channel, *activation.Store) {
		t.Helper()
		store, err := activation.OpenStore(dir, nil)
		require.NoError(t, err)
		channel := fixture.Channel(store, activation.Ledger{LatestConfig: func() (*cb.Block, error) { return genesis, nil }})
		require.NoError(t, channel.Recover(true))
		return &channel, store
	}
	ca, err := tlsgen.NewMLDSA65CA()
	require.NoError(t, err)
	serverKey, err := ca.NewServerCertKeyPair("127.0.0.1")
	require.NoError(t, err)
	remoteKey, err := ca.NewClientCertKeyPair()
	require.NoError(t, err)
	remoteCert, err := tls.X509KeyPair(remoteKey.Cert, remoteKey.Key)
	require.NoError(t, err)
	serverCert, err := tls.X509KeyPair(serverKey.Cert, serverKey.Key)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(ca.CertBytes()))
	provider := &disabled.Provider{}
	log := flogging.MustGetLogger("pq40e.mixed.cluster")
	start := func(channel *activation.Channel, store *activation.Store) (ab.ClusterClient, <-chan struct{}, func()) {
		t.Helper()
		policy, err := store.AuthenticateRegistry(channel.Signer, channel.Network, channel.Node)
		require.NoError(t, err)
		server, err := comm.NewGRPCServer("127.0.0.1:0", comm.ServerConfig{SecOpts: comm.SecureOptions{
			UseTLS: true, RequireClientCert: true, Certificate: serverKey.Cert, Key: serverKey.Key,
			ClientRootCAs: [][]byte{ca.CertBytes()}, TransportPolicy: policy,
		}})
		require.NoError(t, err)
		entered := make(chan struct{}, 1)
		makeChain := func(guard *activation.Channel) *Chain {
			chain := &Chain{activation: guard, raftID: 1, startC: make(chan struct{}), doneC: make(chan struct{}), submitC: make(chan *submit)}
			close(chain.startC)
			go func() {
				for {
					select {
					case <-chain.doneC:
						return
					case request := <-chain.submitC:
						request.leader <- 1
						if request.proposal != nil {
							if request.req.GetLastValidationSeq() == 1 {
								entered <- struct{}{}
							} else {
								request.proposal <- nil
							}
						}
					}
				}
			}()
			return chain
		}
		protected, plain := makeChain(channel), makeChain(nil)
		dialer := &cluster.PredicateDialer{Config: comm.ClientConfig{AsyncConnect: true, DialTimeout: time.Second, SecOpts: comm.SecureOptions{
			UseTLS: true, RequireClientCert: true, Certificate: remoteKey.Cert, Key: remoteKey.Key,
			ServerRootCAs: [][]byte{ca.CertBytes()}, TransportPolicy: policy,
		}}}
		clusterMetrics := cluster.NewMetrics(provider)
		transport := &cluster.Comm{
			Logger: log, ChanExt: &Consenter{}, CompareCertificate: bytes.Equal, Metrics: clusterMetrics,
			Connections: cluster.NewConnectionStore(dialer, provider.NewGauge(metrics.GaugeOpts{
				Name: "pq40e_cluster_tls_connections", Help: "Number of open cluster TLS connections.",
			})),
			Chan2Members: make(cluster.MembersByChannel),
			H:            &Dispatcher{Logger: log, ChainSelector: pq40eClusterReceivers{testfixture.ChannelID: protected, baseline: plain}},
		}
		members := []cluster.RemoteNode{{ID: 2, Endpoint: server.Address(), ClientTLSCert: remoteCert.Certificate[0], ServerTLSCert: serverCert.Certificate[0]}}
		transport.Configure(testfixture.ChannelID, members)
		transport.Configure(baseline, members)
		ab.RegisterClusterServer(server.Server(), &cluster.Service{
			Dispatcher: transport, Logger: log, StepLogger: log,
			StreamCountReporter: &cluster.StreamCountReporter{Metrics: clusterMetrics},
		})
		go server.Start()
		connection, err := grpc.NewClient(server.Address(), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
			Certificates: []tls.Certificate{remoteCert}, RootCAs: roots,
		})))
		require.NoError(t, err)
		stop := sync.OnceFunc(func() {
			_ = connection.Close()
			close(protected.doneC)
			close(plain.doneC)
			transport.Shutdown()
			server.Stop()
		})
		t.Cleanup(stop)
		return ab.NewClusterClient(connection), entered, stop
	}
	submit := func(client ab.ClusterClient, channel string, seq uint64) error {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		stream, err := client.Step(ctx)
		if err != nil {
			return err
		}
		if err := stream.Send(&ab.StepRequest{Payload: &ab.StepRequest_SubmitRequest{
			SubmitRequest: &ab.SubmitRequest{Channel: channel, LastValidationSeq: seq},
		}}); err != nil {
			return err
		}
		if err := stream.CloseSend(); err != nil {
			return err
		}
		_, err = stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	channel, store := recoverChannel()
	client, entered, stop := start(channel, store)
	require.NoError(t, submit(client, testfixture.ChannelID, 0))
	result := make(chan error, 1)
	go func() { result <- submit(client, testfixture.ChannelID, 1) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("protected cluster request did not reach the Raft submission queue")
	}
	channel.Suspend()
	require.ErrorContains(t, <-result, "canceled")
	require.ErrorContains(t, submit(client, testfixture.ChannelID, 0), "protected channel admission is closed")
	require.NoError(t, submit(client, baseline, 0))
	stop()

	channel, store = recoverChannel()
	client, _, _ = start(channel, store)
	require.NoError(t, submit(client, testfixture.ChannelID, 0))
	require.NoError(t, submit(client, baseline, 0))
}
