//go:build linux

/*
SPDX-License-Identifier: Apache-2.0
*/

package peer

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hyperledger/fabric-lib-go/common/metrics/disabled"
	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	dp "github.com/hyperledger/fabric-protos-go-apiv2/discovery"
	gossipproto "github.com/hyperledger/fabric-protos-go-apiv2/gossip"
	"github.com/hyperledger/fabric-protos-go-apiv2/ledger/rwset"
	mb "github.com/hyperledger/fabric-protos-go-apiv2/msp"
	ab "github.com/hyperledger/fabric-protos-go-apiv2/orderer"
	pb "github.com/hyperledger/fabric-protos-go-apiv2/peer"
	tspb "github.com/hyperledger/fabric-protos-go-apiv2/transientstore"
	"github.com/hyperledger/fabric/common/channelconfig"
	"github.com/hyperledger/fabric/common/crypto/tlsgen"
	"github.com/hyperledger/fabric/common/deliver"
	fabricerrors "github.com/hyperledger/fabric/common/errors"
	discservice "github.com/hyperledger/fabric/discovery"
	discconfig "github.com/hyperledger/fabric/discovery/support/config"
	"github.com/hyperledger/fabric/internal/pkg/comm"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation/testfixture"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/enrollment"
	"github.com/hyperledger/fabric/protoutil"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	health "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/protobuf/proto"
)

func TestPQ40EMixedPeerPublicationFailureAndRestart(t *testing.T) {
	testMixedPeerPublicationFailureAndRestart(t, false)
}

func TestPQ40B1ManagedPeerPublicationFailureAndRestart(t *testing.T) {
	testMixedPeerPublicationFailureAndRestart(t, true)
}

func testMixedPeerPublicationFailureAndRestart(t *testing.T, transportCapability bool) {
	const baseline = "unchanged-baseline"
	fixture := testfixture.New(t)
	ca := func() tlsgen.CA {
		t.Helper()
		result, err := tlsgen.NewMLDSA65CA()
		require.NoError(t, err)
		return result
	}
	baseCA, oldCA, candidateCA, nodeCA := ca(), ca(), ca(), ca()
	node, err := nodeCA.NewServerCertKeyPair("127.0.0.1")
	require.NoError(t, err)
	configWithRoot := func(base *cb.Config, root []byte) *cb.Config {
		t.Helper()
		conf := proto.CloneOf(base)
		var replace func(*cb.ConfigGroup)
		replace = func(group *cb.ConfigGroup) {
			if value := group.GetValues()["MSP"]; value != nil {
				msp := &mb.MSPConfig{}
				require.NoError(t, proto.Unmarshal(value.GetValue(), msp))
				fabric := &mb.FabricMSPConfig{}
				require.NoError(t, proto.Unmarshal(msp.GetConfig(), fabric))
				fabric.TlsRootCerts = [][]byte{root}
				fabric.TlsIntermediateCerts = nil
				msp.Config = protoutil.MarshalOrPanic(fabric)
				value.Value = protoutil.MarshalOrPanic(msp)
			}
			for _, child := range group.GetGroups() {
				replace(child)
			}
		}
		replace(conf.GetChannelGroup())
		return conf
	}
	makeBlock := func(channel string, number uint64, parent *cb.Block, config *cb.ConfigEnvelope) *cb.Block {
		t.Helper()
		var previous []byte
		if parent != nil {
			previous = protoutil.BlockHeaderHash(parent.GetHeader())
		}
		block := protoutil.NewBlock(number, previous)
		envelope, err := protoutil.CreateSignedEnvelope(cb.HeaderType_CONFIG, channel, fixture.Fabric, config, 0, 0)
		require.NoError(t, err)
		block.Data.Data = [][]byte{protoutil.MarshalOrPanic(envelope)}
		block.Header.DataHash = protoutil.ComputeBlockDataHash(block.GetData())
		block.Metadata.Metadata[cb.BlockMetadataIndex_TRANSACTIONS_FILTER] = []byte{byte(pb.TxValidationCode_VALID)}
		block.Metadata.Metadata[cb.BlockMetadataIndex_LAST_CONFIG] = protoutil.MarshalOrPanic(
			&cb.Metadata{Value: protoutil.MarshalOrPanic(&cb.LastConfig{Index: number})},
		)
		return block
	}

	template := testfixture.Genesis(t)
	baselineBase := configWithRoot(testfixture.Config(t, template), baseCA.CertBytes())
	if transportCapability {
		template = testfixture.TransportGenesis(t)
	}
	protectedBase := configWithRoot(testfixture.Config(t, template), oldCA.CertBytes())
	protectedGenesis := makeBlock(testfixture.ChannelID, 0, nil, &cb.ConfigEnvelope{Config: protectedBase})
	baselineGenesis := makeBlock(baseline, 0, nil, &cb.ConfigEnvelope{Config: baselineBase})
	update := fixture.UpdateTo(t, protectedBase, configWithRoot(protectedBase, candidateCA.CertBytes()))
	protectedBlock := makeBlock(testfixture.ChannelID, 1, protectedGenesis, update)
	baselineNext := fixture.Update(t, baselineBase)
	baselineBlock := makeBlock(baseline, 1, baselineGenesis, fixture.UpdateChannelTo(t, baseline, baselineBase, baselineNext.GetConfig()))

	root, state := t.TempDir(), t.TempDir()
	store, err := activation.OpenStore(state, nil)
	require.NoError(t, err)
	fixture.Provision(t, store, protectedBase)
	key := fixture.Channel(store, activation.Ledger{}).Signer.Bytes()
	keyFile := filepath.Join(state, "policy-key")
	require.NoError(t, os.WriteFile(keyFile, key, 0o600))
	id := sha256.Sum256([]byte(testfixture.ChannelID))
	anchor, err := json.Marshal(hex.EncodeToString(protoutil.BlockHeaderHash(protectedGenesis.GetHeader())))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(state, fmt.Sprintf("genesis-%x", id)), anchor, 0o600))
	approval, err := json.Marshal(fixture.Authorize(t, 1, protectedBase, update.GetConfig()))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(state, fmt.Sprintf("approval-%x-2", id)), approval, 0o600))
	manifest := &enrollment.Manifest{
		Mode: enrollment.Protected, Network: testfixture.Network, Node: testfixture.Node,
		Profile: pqtransport.ProfileV1, PolicySigner: keyFile, PolicySignerDigest: fmt.Sprintf("%x", sha256.Sum256(key)),
		StateDir: state, LedgerDir: filepath.Join(root, "ledgersData"),
	}
	start := func(failRetirement bool) (*Peer, *comm.GRPCServer, *atomic.Uint64, func()) {
		t.Helper()
		p, closeLedger := newTestPeer(t, root)
		registry, err := enrollment.OpenProtectedRegistry(manifest)
		require.NoError(t, err)
		p.ProtectedRegistry = registry
		p.CredentialSupport = comm.NewCredentialSupport()
		p.ServerConfig = comm.ServerConfig{HealthCheckEnabled: true, SecOpts: comm.SecureOptions{
			UseTLS: true, RequireClientCert: true, Certificate: node.Cert, Key: node.Key,
			ClientRootCAs: [][]byte{nodeCA.CertBytes()}, TransportPolicy: registry.TransportPolicy(),
		}}
		p.ServerConfig.ServerStatsHandler = comm.NewServerStatsHandler(&disabled.Provider{})
		server, err := comm.NewGRPCServer("127.0.0.1:0", p.ServerConfig)
		require.NoError(t, err)
		closePeer := sync.OnceFunc(func() {
			server.Stop()
			p.GossipService.Stop()
			p.StoreProvider.Close()
			closeLedger()
		})
		t.Cleanup(closePeer)
		var cacheSequence atomic.Uint64
		require.NoError(t, p.AddProtectedConfigStage(func(bundle *channelconfig.Bundle) (ProtectedConfigPublication, error) {
			seq := bundle.ConfigtxValidator().Sequence()
			return ProtectedConfigPublication{
				Retire: func() error {
					if failRetirement && seq == 1 {
						return errors.New("injected cache retirement failure")
					}
					return nil
				},
				Publish: func() { cacheSequence.Store(seq) },
			}, nil
		}))
		p.Initialize(nil, server, nil, nil, nil, nil, 1)
		pb.RegisterDeliverServer(server.Server(), &DeliverServer{
			DeliverHandler: deliver.NewHandler(&DeliverChainManager{Peer: p}, time.Minute, true, deliver.NewMetrics(&disabled.Provider{}), false),
			PolicyCheckerProvider: func(string) deliver.PolicyCheckerFunc {
				return func(*cb.Envelope, string) error { return nil }
			},
		})
		dp.RegisterDiscoveryServer(server.Server(), discservice.NewService(discservice.Config{
			TLS: true, AuthCacheEnabled: true, AuthCacheMaxSize: 10, AuthCachePurgeRetentionRatio: 0.5,
			AcquireAdmission: p.AcquireChannelAdmission,
		}, mixedDiscoverySupport{peer: p}))
		go server.Start()
		return p, server, &cacheSequence, closePeer
	}
	dial := func(server *comm.GRPCServer, clientCA tlsgen.CA) (*grpc.ClientConn, [sha256.Size]byte) {
		t.Helper()
		key, err := clientCA.NewClientCertKeyPair()
		require.NoError(t, err)
		cert, err := tls.X509KeyPair(key.Cert, key.Key)
		require.NoError(t, err)
		roots := x509.NewCertPool()
		require.True(t, roots.AppendCertsFromPEM(nodeCA.CertBytes()))
		client, err := grpc.NewClient(server.Address(), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
			RootCAs: roots, Certificates: []tls.Certificate{cert},
		})))
		require.NoError(t, err)
		return client, sha256.Sum256(cert.Certificate[0])
	}
	accepts := func(server *comm.GRPCServer, clientCA tlsgen.CA) error {
		t.Helper()
		client, _ := dial(server, clientCA)
		defer client.Close()
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		defer cancel()
		_, err := health.NewHealthClient(client).Check(ctx, &health.HealthCheckRequest{})
		return err
	}
	checkDiscovery := func(server *comm.GRPCServer, protectedAvailable bool) {
		t.Helper()
		client, hash := dial(server, baseCA)
		defer client.Close()
		identity, err := fixture.Fabric.Serialize()
		require.NoError(t, err)
		request := &dp.Request{
			Authentication: &dp.AuthInfo{ClientIdentity: identity, ClientTlsCertHash: hash[:]},
			Queries: []*dp.Query{
				{Channel: testfixture.ChannelID, Query: &dp.Query_ConfigQuery{ConfigQuery: &dp.ConfigQuery{}}},
				{Channel: baseline, Query: &dp.Query_ConfigQuery{ConfigQuery: &dp.ConfigQuery{}}},
			},
		}
		payload := protoutil.MarshalOrPanic(request)
		signature, err := fixture.Fabric.Sign(payload)
		require.NoError(t, err)
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		defer cancel()
		response, err := dp.NewDiscoveryClient(client).Discover(ctx, &dp.SignedRequest{Payload: payload, Signature: signature})
		require.NoError(t, err)
		require.Len(t, response.GetResults(), 2)
		if protectedAvailable {
			require.NotNil(t, response.GetResults()[0].GetConfigResult(), "%v", response.GetResults()[0])
		} else {
			require.Equal(t, "access denied", response.GetResults()[0].GetError().GetContent())
		}
		require.NotNil(t, response.GetResults()[1].GetConfigResult())
	}
	seek := func(client *grpc.ClientConn, hash [sha256.Size]byte, cid string, start uint64) pb.Deliver_DeliverClient {
		t.Helper()
		env, err := protoutil.CreateSignedEnvelopeWithTLSBinding(cb.HeaderType_DELIVER_SEEK_INFO, cid, fixture.Fabric, &ab.SeekInfo{
			Start:         &ab.SeekPosition{Type: &ab.SeekPosition_Specified{Specified: &ab.SeekSpecified{Number: start}}},
			Stop:          &ab.SeekPosition{Type: &ab.SeekPosition_Specified{Specified: &ab.SeekSpecified{Number: math.MaxUint64}}},
			Behavior:      ab.SeekInfo_BLOCK_UNTIL_READY,
			ErrorResponse: ab.SeekInfo_BEST_EFFORT,
		}, 0, 0, hash[:])
		require.NoError(t, err)
		ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
		t.Cleanup(cancel)
		stream, err := pb.NewDeliverClient(client).Deliver(ctx)
		require.NoError(t, err)
		require.NoError(t, stream.Send(env))
		return stream
	}
	checkBlock := func(stream pb.Deliver_DeliverClient, expected *cb.Block) {
		t.Helper()
		resp, err := stream.Recv()
		require.NoError(t, err)
		require.NotNil(t, resp.GetBlock(), "%v", resp)
		require.Equal(t, protoutil.BlockHeaderHash(expected.GetHeader()), protoutil.BlockHeaderHash(resp.GetBlock().GetHeader()))
	}
	distribute := func(p *Peer, channel, txid string) error {
		return p.GossipService.DistributePrivateData(channel, txid, &tspb.TxPvtReadWriteSetWithConfigInfo{
			PvtRwset: &rwset.TxPvtReadWriteSet{},
		}, 1)
	}
	enqueue := func(p *Peer, channel string, block *cb.Block) error {
		return p.GossipService.AddPayload(channel, &gossipproto.Payload{
			SeqNum: block.GetHeader().GetNumber(), Data: protoutil.MarshalOrPanic(block),
		})
	}

	p, server, cache, closePeer := start(true)
	require.NoError(t, p.CreateChannel(baseline, baselineGenesis, nil, nil, nil))
	require.NoError(t, p.CreateChannel(testfixture.ChannelID, protectedGenesis, nil, nil, nil))
	require.NoError(t, accepts(server, baseCA))
	require.NoError(t, accepts(server, oldCA))
	require.Error(t, accepts(server, candidateCA))
	checkDiscovery(server, true)
	client, hash := dial(server, baseCA)
	t.Cleanup(func() { _ = client.Close() })
	protectedDeliver := seek(client, hash, testfixture.ChannelID, 0)
	baselineDeliver := seek(client, hash, baseline, 0)
	checkBlock(protectedDeliver, protectedGenesis)
	checkBlock(baselineDeliver, baselineGenesis)
	require.NoError(t, distribute(p, testfixture.ChannelID, "protected-before"))
	require.NoError(t, enqueue(p, testfixture.ChannelID, protectedBlock))
	require.Eventually(t, func() bool {
		return errors.Is(enqueue(p, testfixture.ChannelID, protectedBlock), fabricerrors.ErrProtectedChannelRecovery)
	}, 10*time.Second, 50*time.Millisecond)
	_, _, allowed := p.AcquireChannelAdmission(testfixture.ChannelID)
	require.False(t, allowed)
	_, _, allowed = p.AcquireChannelAdmission(baseline)
	require.True(t, allowed)
	require.Zero(t, cache.Load())
	require.NoError(t, accepts(server, baseCA))
	require.NoError(t, accepts(server, oldCA))
	require.Error(t, accepts(server, candidateCA))
	checkDiscovery(server, false)
	closed, err := protectedDeliver.Recv()
	require.NoError(t, err)
	require.Equal(t, cb.Status_SERVICE_UNAVAILABLE, closed.GetStatus())
	require.ErrorContains(t, distribute(p, testfixture.ChannelID, "protected-closed"), "admission is closed")
	require.NoError(t, distribute(p, baseline, "baseline-live"))
	require.NoError(t, enqueue(p, baseline, baselineBlock))
	checkBlock(baselineDeliver, baselineBlock)
	require.Eventually(t, func() bool {
		height, err := p.Channel(baseline).Ledger().GetBlockchainInfo()
		return err == nil && height.GetHeight() == 2
	}, 10*time.Second, 50*time.Millisecond)
	persisted, err := RetrievePersistedChannelConfig(p.Channel(testfixture.ChannelID).Ledger())
	require.NoError(t, err)
	require.EqualValues(t, 1, persisted.GetSequence(), "the protected config must be durable before the injected failure")
	closePeer()

	p, server, cache, _ = start(false)
	generation, release, allowed := p.AcquireChannelAdmission(testfixture.ChannelID)
	require.True(t, allowed)
	require.NoError(t, generation.Err())
	release()
	require.EqualValues(t, 1, p.Channel(testfixture.ChannelID).Sequence())
	require.EqualValues(t, 1, p.Channel(baseline).Sequence())
	require.EqualValues(t, 1, cache.Load())
	require.NoError(t, accepts(server, baseCA))
	require.NoError(t, accepts(server, candidateCA))
	require.Error(t, accepts(server, oldCA))
	checkDiscovery(server, true)
	restartedClient, restartedHash := dial(server, baseCA)
	t.Cleanup(func() { _ = restartedClient.Close() })
	checkBlock(seek(restartedClient, restartedHash, testfixture.ChannelID, 1), protectedBlock)
	require.NoError(t, distribute(p, testfixture.ChannelID, "protected-recovered"))
	require.NoError(t, distribute(p, baseline, "baseline-recovered"))
	if transportCapability {
		current := testfixture.Config(t, protectedBlock)
		next := fixture.Update(t, current)
		weakened := fixture.AuthorizeWithProfile(t, 2, current, next.GetConfig(), "classical")
		encoded, err := json.Marshal(weakened)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(state, fmt.Sprintf("approval-%x-3", id)), encoded, 0o600))
		attempt := makeBlock(testfixture.ChannelID, 2, protectedBlock, next)
		require.NoError(t, enqueue(p, testfixture.ChannelID, attempt))
		require.Eventually(t, func() bool {
			_, release, admitted := p.AcquireChannelAdmission(testfixture.ChannelID)
			if release != nil {
				release()
			}
			return !admitted
		}, 10*time.Second, 50*time.Millisecond)
		_, release, admitted := p.AcquireChannelAdmission(baseline)
		require.True(t, admitted)
		if release != nil {
			release()
		}
		persisted, err := RetrievePersistedChannelConfig(p.Channel(testfixture.ChannelID).Ledger())
		require.NoError(t, err)
		require.EqualValues(t, 1, persisted.GetSequence())
		weakClient, err := baseCA.NewClientCertKeyPair()
		require.NoError(t, err)
		cert, err := tls.X509KeyPair(weakClient.Cert, weakClient.Key)
		require.NoError(t, err)
		roots := x509.NewCertPool()
		require.True(t, roots.AppendCertsFromPEM(nodeCA.CertBytes()))
		weakConn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", server.Address(), &tls.Config{
			RootCAs: roots, ServerName: "127.0.0.1", Certificates: []tls.Certificate{cert},
			MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519},
		})
		if weakConn != nil {
			_ = weakConn.Close()
		}
		require.Error(t, err, "shared listener accepted classical key exchange")
	}
}

type mixedDiscoverySupport struct {
	discservice.Support
	peer *Peer
}

func (s mixedDiscoverySupport) ChannelExists(id string) bool {
	return s.peer.Channel(id) != nil
}

func (s mixedDiscoverySupport) EligibleForService(string, protoutil.SignedData) error { return nil }

func (s mixedDiscoverySupport) ConfigSequence(id string) uint64 {
	return s.peer.Channel(id).Sequence()
}

func (s mixedDiscoverySupport) Config(id string) (*dp.ConfigResult, error) {
	support := discconfig.NewDiscoverySupport(discconfig.CurrentConfigGetterFunc(func(channel string) *cb.Config {
		config, _ := RetrievePersistedChannelConfig(s.peer.Channel(channel).Ledger())
		return config
	}))
	return support.Config(id)
}
