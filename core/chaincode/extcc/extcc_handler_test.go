/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package extcc_test

import (
	"errors"
	"net"
	"testing"
	"time"

	pb "github.com/hyperledger/fabric-protos-go-apiv2/peer"
	"github.com/hyperledger/fabric/common/crypto/tlsgen"
	"github.com/hyperledger/fabric/core/chaincode/extcc"
	"github.com/hyperledger/fabric/core/chaincode/extcc/mock"
	"github.com/hyperledger/fabric/core/container/ccintf"
	"github.com/hyperledger/fabric/internal/pkg/comm"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

func TestPQ40EAbortExternalChaincodeStream(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := grpc.NewServer()
	t.Cleanup(server.Stop)
	probe := &abortProbe{entered: make(chan struct{}), ended: make(chan struct{})}
	pb.RegisterChaincodeServer(server, probe)
	go server.Serve(listener)

	handler := &mock.StreamHandler{}
	handler.HandleChaincodeStreamCalls(func(stream ccintf.ChaincodeStream) error {
		select {
		case <-probe.entered:
		case <-time.After(5 * time.Second):
			t.Fatal("external shim stream did not open")
		}
		aborter, ok := stream.(interface{ Abort() })
		require.True(t, ok)
		aborter.Abort()
		_, err := stream.Recv()
		require.Error(t, err)
		select {
		case <-probe.ended:
		case <-time.After(5 * time.Second):
			t.Fatal("external shim still has an open RPC after abort")
		}
		return nil
	})
	runtime := &extcc.ExternalChaincodeRuntime{}
	require.NoError(t, runtime.Stream("cc", &ccintf.ChaincodeServerInfo{
		Address: listener.Addr().String(), ClientConfig: comm.ClientConfig{DialTimeout: 5 * time.Second},
	}, handler))
}

type abortProbe struct {
	pb.UnimplementedChaincodeServer
	entered, ended chan struct{}
}

func (p *abortProbe) Connect(stream pb.Chaincode_ConnectServer) error {
	close(p.entered)
	defer close(p.ended)
	<-stream.Context().Done()
	return stream.Context().Err()
}

var _ = Describe("Extcc", func() {
	var (
		i        *extcc.ExternalChaincodeRuntime
		shandler *mock.StreamHandler
	)

	BeforeEach(func() {
		shandler = &mock.StreamHandler{}
		i = &extcc.ExternalChaincodeRuntime{}
	})

	Context("Run", func() {
		When("chaincode is running", func() {
			var (
				cclist net.Listener
				ccserv *grpc.Server
			)
			BeforeEach(func() {
				var err error
				cclist, err = net.Listen("tcp", "127.0.0.1:0")
				Expect(err).To(BeNil())
				Expect(cclist).To(Not(BeNil()))
				ccserv = grpc.NewServer([]grpc.ServerOption{}...)
				go ccserv.Serve(cclist)
			})

			AfterEach(func() {
				if ccserv != nil {
					ccserv.Stop()
				}
				if cclist != nil {
					cclist.Close()
				}
			})

			It("runs to completion", func() {
				ccinfo := &ccintf.ChaincodeServerInfo{
					Address: cclist.Addr().String(),
					ClientConfig: comm.ClientConfig{
						KaOpts:      comm.DefaultKeepaliveOptions,
						DialTimeout: 10 * time.Second,
					},
				}
				err := i.Stream("ccid", ccinfo, shandler)
				Expect(err).To(BeNil())
				Expect(shandler.HandleChaincodeStreamCallCount()).To(Equal(1))

				streamArg := shandler.HandleChaincodeStreamArgsForCall(0)
				Expect(streamArg).To(Not(BeNil()))
			})

			It("HandleChaincodeStream returns error", func() {
				ccinfo := &ccintf.ChaincodeServerInfo{
					Address: cclist.Addr().String(),
					ClientConfig: comm.ClientConfig{
						KaOpts:      comm.DefaultKeepaliveOptions,
						DialTimeout: 10 * time.Second,
					},
				}
				shandler.HandleChaincodeStreamReturns(errors.New("error returned by HandleChaincodeStream"))
				err := i.Stream("ccid", ccinfo, shandler)
				Expect(err).To(MatchError(ContainSubstring("error handling chaincode stream for ccid")))
			})
		})
		Context("chaincode info incorrect", func() {
			var ccinfo *ccintf.ChaincodeServerInfo
			BeforeEach(func() {
				ca, err := tlsgen.NewCA()
				Expect(err).NotTo(HaveOccurred())
				ckp, err := ca.NewClientCertKeyPair()
				Expect(err).NotTo(HaveOccurred())
				ccinfo = &ccintf.ChaincodeServerInfo{
					Address: "ccaddress:12345",
					ClientConfig: comm.ClientConfig{
						SecOpts: comm.SecureOptions{
							UseTLS:            true,
							RequireClientCert: true,
							Certificate:       ckp.Cert,
							Key:               ckp.Key,
							ServerRootCAs:     [][]byte{ca.CertBytes()},
						},
						DialTimeout: 10 * time.Second,
					},
				}
			})
			When("address is bad", func() {
				BeforeEach(func() {
					ccinfo.ClientConfig.SecOpts.UseTLS = false
					ccinfo.Address = "<badaddress>"
				})
				It("returns an error", func() {
					err := i.Stream("ccid", ccinfo, shandler)
					Expect(err).To(MatchError(ContainSubstring("error creating grpc connection to <badaddress>")))
				})
			})
			When("unspecified client spec", func() {
				BeforeEach(func() {
					ccinfo.ClientConfig.SecOpts.Key = nil
				})
				It("returns an error", func() {
					err := i.Stream("ccid", ccinfo, shandler)
					Expect(err).To(MatchError(ContainSubstring("both Key and Certificate are required when using mutual TLS")))
				})
			})
		})
	})
})
