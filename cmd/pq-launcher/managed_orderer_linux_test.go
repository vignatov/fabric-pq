//go:build linux

/*
SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"bytes"
	"context"
	"crypto/mldsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/hyperledger/fabric-lib-go/common/metrics/disabled"
	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	mb "github.com/hyperledger/fabric-protos-go-apiv2/msp"
	ab "github.com/hyperledger/fabric-protos-go-apiv2/orderer"
	pb "github.com/hyperledger/fabric-protos-go-apiv2/orderer/etcdraft"
	peerpb "github.com/hyperledger/fabric-protos-go-apiv2/peer"
	"github.com/hyperledger/fabric/common/channelconfig"
	"github.com/hyperledger/fabric/common/crypto/tlsgen"
	"github.com/hyperledger/fabric/common/ledger/blockledger/fileledger"
	"github.com/hyperledger/fabric/core/config/configtest"
	coreledger "github.com/hyperledger/fabric/core/ledger"
	"github.com/hyperledger/fabric/core/scc/cscc"
	"github.com/hyperledger/fabric/core/scc/qscc"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation/testfixture"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/enrollment"
	"github.com/hyperledger/fabric/orderer/common/channelparticipation"
	"github.com/hyperledger/fabric/orderer/common/types"
	"github.com/hyperledger/fabric/protoutil"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func TestPQ40EManagedOrdererRestart(t *testing.T) {
	testManagedOrdererRestart(t, false)
}

func TestPQ40B1ManagedOrdererRestart(t *testing.T) {
	testManagedOrdererRestart(t, true)
}

func testManagedOrdererRestart(t *testing.T, transportCapability bool) {
	if os.Getenv("PQ40E_MANAGED_TEST_CHILD") == "1" {
		if err := run(os.Getenv("PQ40E_AUTHORITY"), os.Getenv("PQ40E_MANIFEST"), os.Getenv("PQ40E_HISTORY")); err != nil {
			_, _ = os.Stderr.WriteString(err.Error())
			os.Exit(2)
		}
		os.Exit(0)
	}
	binary := os.Getenv("PQ40E_MANAGED_ORDERER")
	if binary == "" {
		t.Skip("set PQ40E_MANAGED_ORDERER to the built orderer")
	}
	root := t.TempDir()
	write := func(name string, data []byte) string {
		t.Helper()
		path := filepath.Join(root, name)
		require.NoError(t, os.WriteFile(path, data, 0o600))
		return path
	}
	ca, err := tlsgen.NewMLDSA65CA()
	require.NoError(t, err)
	node, err := ca.NewServerCertKeyPair("127.0.0.1")
	require.NoError(t, err)
	clientKey, err := ca.NewClientCertKeyPair()
	require.NoError(t, err)
	certFile, keyFile, caFile := write("tls.crt", node.Cert), write("tls.key", node.Key), write("ca.crt", ca.CertBytes())
	state, ledger := filepath.Join(root, "state"), filepath.Join(root, "ledger")
	require.NoError(t, os.Mkdir(state, 0o700))
	require.NoError(t, os.Mkdir(ledger, 0o700))

	mainPort, adminPort, operationsPort := unusedPort(t), unusedPort(t), unusedPort(t)
	fixture := testfixture.New(t)
	genesis := managedGenesis(t, fixture, ca.CertBytes(), node.Cert, mainPort, transportCapability)
	t.Logf("managed orderer binary=%q command=start genesis_sha256=%x", binary, sha256.Sum256(protoutil.MarshalOrPanic(genesis)))
	factory, err := fileledger.New(ledger, coreledger.GoLevelDB, &disabled.Provider{})
	require.NoError(t, err)
	channel, err := factory.GetOrCreate(testfixture.ChannelID)
	require.NoError(t, err)
	require.NoError(t, channel.Append(genesis))
	const baseline = "unchanged-baseline"
	base := testfixture.Config(t, genesis)
	baselineGenesis := managedGenesis(t, fixture, ca.CertBytes(), node.Cert, mainPort)
	baselineBase := testfixture.Config(t, baselineGenesis)
	baselineEnvelope, err := protoutil.CreateSignedEnvelope(cb.HeaderType_CONFIG, baseline, fixture.Fabric, &cb.ConfigEnvelope{Config: baselineBase}, 0, 0)
	require.NoError(t, err)
	baselineGenesis.Data.Data[0] = protoutil.MarshalOrPanic(baselineEnvelope)
	baselineGenesis.Header.DataHash = protoutil.ComputeBlockDataHash(baselineGenesis.GetData())
	baselineLedger, err := factory.GetOrCreate(baseline)
	require.NoError(t, err)
	require.NoError(t, baselineLedger.Append(baselineGenesis))
	factory.Close()
	store, err := activation.OpenStore(state, nil)
	require.NoError(t, err)
	fixture.Provision(t, store, base)
	channelHash := sha256.Sum256([]byte(testfixture.ChannelID))
	anchor, err := json.Marshal(hex.EncodeToString(protoutil.BlockHeaderHash(genesis.GetHeader())))
	require.NoError(t, err)
	write(filepath.Join("state", "genesis-"+hex.EncodeToString(channelHash[:])), anchor)
	update := fixture.Update(t, base)
	baselineUpdate := fixture.UpdateChannelTo(t, baseline, baselineBase, fixture.Update(t, baselineBase).GetConfig())
	authorization, err := json.Marshal(fixture.Authorize(t, 1, base, update.GetConfig()))
	require.NoError(t, err)
	write(filepath.Join("state", "approval-"+hex.EncodeToString(channelHash[:])+"-2"), authorization)
	adminUpdate := fixture.Update(t, update.GetConfig())
	adminApproval, err := json.Marshal(fixture.Authorize(t, 2, update.GetConfig(), adminUpdate.GetConfig()))
	require.NoError(t, err)
	write(filepath.Join("state", "approval-"+hex.EncodeToString(channelHash[:])+"-3"), adminApproval)
	environment := append(managedEvidence(t, root, state, ledger, binary, []string{"start"}, fixture, store),
		"FABRIC_CFG_PATH="+configtest.GetDevConfigDir(), "ORDERER_GENERAL_BOOTSTRAPMETHOD=none",
		"ORDERER_GENERAL_LOCALMSPDIR="+configtest.GetDevMspDir(), "ORDERER_GENERAL_LISTENADDRESS=127.0.0.1",
		"ORDERER_GENERAL_LISTENPORT="+mainPort, "ORDERER_FILELEDGER_LOCATION="+ledger,
		"ORDERER_GENERAL_TLS_ENABLED=true", "ORDERER_GENERAL_TLS_CLIENTAUTHREQUIRED=true",
		"ORDERER_GENERAL_TLS_CERTIFICATE="+certFile, "ORDERER_GENERAL_TLS_PRIVATEKEY="+keyFile,
		"ORDERER_GENERAL_TLS_ROOTCAS="+caFile, "ORDERER_GENERAL_TLS_CLIENTROOTCAS="+caFile, "ORDERER_GENERAL_CLUSTER_ROOTCAS="+caFile,
		"ORDERER_ADMIN_LISTENADDRESS=127.0.0.1:"+adminPort, "ORDERER_ADMIN_TLS_ENABLED=true",
		"ORDERER_ADMIN_TLS_CERTIFICATE="+certFile, "ORDERER_ADMIN_TLS_PRIVATEKEY="+keyFile,
		"ORDERER_ADMIN_TLS_CLIENTAUTHREQUIRED=true", "ORDERER_ADMIN_TLS_CLIENTROOTCAS="+caFile,
		"ORDERER_OPERATIONS_LISTENADDRESS=127.0.0.1:"+operationsPort, "ORDERER_OPERATIONS_TLS_ENABLED=true",
		"ORDERER_OPERATIONS_TLS_CERTIFICATE="+certFile, "ORDERER_OPERATIONS_TLS_PRIVATEKEY="+keyFile,
		"ORDERER_OPERATIONS_TLS_CLIENTAUTHREQUIRED=true", "ORDERER_OPERATIONS_TLS_CLIENTROOTCAS="+caFile,
		"ORDERER_CONSENSUS_WALDIR="+filepath.Join(ledger, "wal"),
		"ORDERER_CONSENSUS_SNAPDIR="+filepath.Join(ledger, "snap"),
	)
	command := func() *exec.Cmd {
		cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^"+t.Name()+"$")
		cmd.Env = append(os.Environ(), environment...)
		return cmd
	}
	requireManagedStartupRejected(t, command(), "ORDERER_OPERATIONS_TLS_ENABLED=false", "protected HTTP listener requires TLS")
	requireManagedStartupRejected(t, command(), "ORDERER_GENERAL_PROFILE_ENABLED=true", "forbids the profiling listener")

	cert, err := tls.X509KeyPair(clientKey.Cert, clientKey.Key)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(ca.CertBytes()))
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:          pool,
			Certificates:     []tls.Certificate{cert},
			MinVersion:       tls.VersionTLS13,
			CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
		},
	}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: time.Second}
	adminURL := "https://127.0.0.1:" + adminPort + "/participation/v1/channels"
	url := adminURL + "/" + testfixture.ChannelID
	for run := range 2 {
		cmd := command()
		log, err := os.CreateTemp(root, "orderer-*.log")
		require.NoError(t, err)
		cmd.Stdout, cmd.Stderr = log, log
		require.NoError(t, cmd.Start())
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		t.Cleanup(func() {
			_ = cmd.Process.Kill()
			_ = log.Close()
			if t.Failed() {
				trace, _ := os.ReadFile(log.Name())
				t.Logf("managed orderer log:\n%s", trace)
			}
		})
		require.Eventually(t, func() bool {
			response, err := client.Get(url)
			if err != nil {
				return false
			}
			defer response.Body.Close()
			var info types.ChannelInfo
			return response.StatusCode == http.StatusOK && response.TLS.CurveID == tls.X25519MLKEM768 &&
				json.NewDecoder(response.Body).Decode(&info) == nil && info.Name == testfixture.ChannelID &&
				info.Status == types.StatusActive
		}, 15*time.Second, 100*time.Millisecond)
		verifyManagedOperations(t, "127.0.0.1:"+operationsPort, transport.TLSClientConfig)
		classical := transport.Clone()
		classical.TLSClientConfig.CurvePreferences = []tls.CurveID{tls.X25519}
		rejected, err := (&http.Client{Transport: classical, Timeout: time.Second}).Get(url)
		if rejected != nil {
			_ = rejected.Body.Close()
		}
		classical.CloseIdleConnections()
		require.Error(t, err)
		for _, tc := range []struct {
			method, endpoint string
			status           int
		}{
			{http.MethodGet, url + "/blocks/config", http.StatusForbidden},
			{http.MethodDelete, url, http.StatusForbidden},
			{http.MethodGet, adminURL + "/" + baseline + "/blocks/config", http.StatusOK},
		} {
			request, err := http.NewRequestWithContext(t.Context(), tc.method, tc.endpoint, nil)
			require.NoError(t, err)
			response, err := client.Do(request)
			require.NoError(t, err)
			require.NoError(t, response.Body.Close())
			require.Equal(t, tc.status, response.StatusCode, tc.endpoint)
		}
		connection, err := grpc.NewClient("127.0.0.1:"+mainPort, grpc.WithTransportCredentials(credentials.NewTLS(transport.TLSClientConfig.Clone())))
		require.NoError(t, err)
		t.Cleanup(func() { _ = connection.Close() })
		atomicBroadcast := ab.NewAtomicBroadcastClient(connection)
		clientHash := sha256.Sum256(cert.Certificate[0])
		deliver, block := managedDeliver(t, atomicBroadcast, fixture, testfixture.ChannelID, uint64(run)*2, clientHash[:])
		baselineStream, baselineBlock := managedDeliver(t, atomicBroadcast, fixture, baseline, uint64(run), clientHash[:])
		if run == 0 {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			broadcast, err := atomicBroadcast.Broadcast(ctx)
			require.NoError(t, err)
			require.NoError(t, broadcast.Send(update.GetLastUpdate()))
			ack, err := broadcast.Recv()
			require.NoError(t, err)
			require.Equal(t, cb.Status_SUCCESS, ack.GetStatus(), ack.GetInfo())
			revoked, err := deliver.Recv()
			require.NoError(t, err)
			require.Equal(t, cb.Status_SERVICE_UNAVAILABLE, revoked.GetStatus(), "old Deliver stream survived generation closure")
			deliver, _ = managedDeliver(t, atomicBroadcast, fixture, testfixture.ChannelID, 1, clientHash[:])
			require.NoError(t, broadcast.Send(baselineUpdate.GetLastUpdate()))
			ack, err = broadcast.Recv()
			require.NoError(t, err)
			require.Equal(t, cb.Status_SUCCESS, ack.GetStatus(), ack.GetInfo())
			response, err := baselineStream.Recv()
			require.NoError(t, err)
			baselineBlock = response.GetBlock()
			require.NotNil(t, baselineBlock, "baseline Deliver must stay active through protected generation closure")
			updateViaManagedAdmin(t, client, adminURL, adminUpdate.GetLastUpdate())
			revoked, err = deliver.Recv()
			require.NoError(t, err)
			require.Equal(t, cb.Status_SERVICE_UNAVAILABLE, revoked.GetStatus())
			_, block = managedDeliver(t, atomicBroadcast, fixture, testfixture.ChannelID, 2, clientHash[:])
		}
		require.EqualValues(t, 2, testfixture.Config(t, block).GetSequence())
		require.EqualValues(t, 1, testfixture.Config(t, baselineBlock).GetSequence())
		require.NoError(t, connection.Close())
		transport.CloseIdleConnections()
		require.NoError(t, cmd.Process.Signal(syscall.SIGTERM))
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-time.After(5 * time.Second):
			t.Fatal("managed orderer did not stop")
		}
	}
	require.NoError(t, os.Remove(filepath.Join(state, "checkpoint")))
	output, err := command().CombinedOutput()
	require.Error(t, err)
	require.Contains(t, string(output), "checkpoint")
}

func updateViaManagedAdmin(t *testing.T, client *http.Client, url string, env *cb.Envelope) {
	t.Helper()
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	file, err := form.CreateFormFile(channelparticipation.FormDataConfigUpdateEnvelopeKey, "update.pb")
	require.NoError(t, err)
	_, err = file.Write(protoutil.MarshalOrPanic(env))
	require.NoError(t, err)
	require.NoError(t, form.Close())
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPut, url, &body)
	require.NoError(t, err)
	request.Header.Set("Content-Type", form.FormDataContentType())
	response, err := client.Do(request)
	require.NoError(t, err)
	defer response.Body.Close()
	require.Equal(t, http.StatusCreated, response.StatusCode)
}

func managedDeliver(t *testing.T, client ab.AtomicBroadcastClient, fixture testfixture.Fixture, channel string, start uint64, hash []byte) (ab.AtomicBroadcast_DeliverClient, *cb.Block) {
	t.Helper()
	seek, err := protoutil.CreateSignedEnvelopeWithTLSBinding(cb.HeaderType_DELIVER_SEEK_INFO, channel, fixture.Fabric,
		&ab.SeekInfo{
			Start:    &ab.SeekPosition{Type: &ab.SeekPosition_Specified{Specified: &ab.SeekSpecified{Number: start}}},
			Stop:     &ab.SeekPosition{Type: &ab.SeekPosition_Specified{Specified: &ab.SeekSpecified{Number: math.MaxUint64}}},
			Behavior: ab.SeekInfo_BLOCK_UNTIL_READY, ErrorResponse: ab.SeekInfo_BEST_EFFORT,
		}, 0, 0, hash)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	t.Cleanup(cancel)
	for ctx.Err() == nil {
		deliver, err := client.Deliver(ctx)
		require.NoError(t, err)
		require.NoError(t, deliver.Send(seek))
		response, err := deliver.Recv()
		require.NoError(t, err)
		if block := response.GetBlock(); block != nil {
			require.Equal(t, start, block.GetHeader().GetNumber())
			return deliver, block
		}
		require.Equal(t, cb.Status_SERVICE_UNAVAILABLE, response.GetStatus(), "unexpected delivery response")
		require.NoError(t, deliver.CloseSend())
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("managed orderer did not open Deliver admission for %s", channel)
	return nil, nil
}

func unusedPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	_, port, err := net.SplitHostPort(l.Addr().String())
	require.NoError(t, err)
	require.NoError(t, l.Close())
	return port
}

func managedEvidence(t *testing.T, root, state, ledger, binary string, args []string, fixture testfixture.Fixture, store *activation.Store) []string {
	t.Helper()
	write := func(name string, data []byte) string {
		path := filepath.Join(root, name)
		require.NoError(t, os.WriteFile(path, data, 0o600))
		return path
	}
	signer := fixture.Channel(store, activation.Ledger{}).Signer.Bytes()
	digest := sha256.Sum256(signer)
	manifest := enrollment.Manifest{
		Network: testfixture.Network, Node: testfixture.Node, Mode: enrollment.Protected, Generation: 1,
		Executable: binary, Arguments: args, Profile: pqtransport.ProfileV1,
		StateDir: state, LedgerDir: ledger, PolicySigner: write("policy.pub", signer),
		PolicySignerDigest: hex.EncodeToString(digest[:]),
	}
	payload, err := json.Marshal(manifest)
	require.NoError(t, err)
	digest = sha256.Sum256(payload)
	history := enrollment.History{
		Network: manifest.Network, Node: manifest.Node, Generation: 1,
		ProtectedEver: true, ManifestDigest: hex.EncodeToString(digest[:]),
	}
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	return []string{
		"PQ40E_MANAGED_TEST_CHILD=1",
		"PQ40E_AUTHORITY=" + write("authority", key.Public().(*mldsa.PublicKey).Bytes()),
		"PQ40E_MANIFEST=" + write("manifest", signed(t, key, "fabric-pq/enrollment/v1\x00", manifest)),
		"PQ40E_HISTORY=" + write("history", signed(t, key, "fabric-pq/enrollment-history/v1\x00", history)),
	}
}

func TestPQ40EManagedPeerRestart(t *testing.T) {
	testManagedPeerRestart(t, false)
}

func TestPQ40B1ManagedPeerRestart(t *testing.T) {
	testManagedPeerRestart(t, true)
}

func testManagedPeerRestart(t *testing.T, transportCapability bool) {
	binary := os.Getenv("PQ40E_MANAGED_PEER")
	if binary == "" {
		t.Skip("set PQ40E_MANAGED_PEER to the built peer")
	}
	root := t.TempDir()
	write := func(name string, data []byte) string {
		path := filepath.Join(root, name)
		require.NoError(t, os.WriteFile(path, data, 0o600))
		return path
	}
	rootCA, err := tlsgen.NewMLDSA65CA()
	require.NoError(t, err)
	serverKey, err := rootCA.NewServerCertKeyPair("127.0.0.1")
	require.NoError(t, err)
	clientKey, err := rootCA.NewClientCertKeyPair()
	require.NoError(t, err)
	state, ledgerRoot := filepath.Join(root, "state"), filepath.Join(root, "peer", "ledgersData")
	require.NoError(t, os.MkdirAll(ledgerRoot, 0o700))
	require.NoError(t, os.Mkdir(state, 0o700))
	fixture := testfixture.New(t)
	genesis := managedGenesis(t, fixture, rootCA.CertBytes(), serverKey.Cert, unusedPort(t), transportCapability)
	t.Logf("managed peer binary=%q command=node start genesis_sha256=%x", binary, sha256.Sum256(protoutil.MarshalOrPanic(genesis)))
	genesisPath := write("genesis.block", protoutil.MarshalOrPanic(genesis))
	store, err := activation.OpenStore(state, nil)
	require.NoError(t, err)
	fixture.Provision(t, store, testfixture.Config(t, genesis))
	id := sha256.Sum256([]byte(testfixture.ChannelID))
	anchor, err := json.Marshal(hex.EncodeToString(protoutil.BlockHeaderHash(genesis.GetHeader())))
	require.NoError(t, err)
	write(filepath.Join("state", "genesis-"+hex.EncodeToString(id[:])), anchor)
	evidence := managedEvidence(t, root, state, ledgerRoot, binary, []string{"node", "start"}, fixture, store)
	peerAddress := "127.0.0.1:" + unusedPort(t)
	ccAddress := "127.0.0.1:" + unusedPort(t)
	operationsAddress := "127.0.0.1:" + unusedPort(t)
	certFile, keyFile, caFile := write("peer.crt", serverKey.Cert), write("peer.key", serverKey.Key), write("ca.crt", rootCA.CertBytes())
	env := append(os.Environ(),
		"FABRIC_CFG_PATH="+configtest.GetDevConfigDir(),
		"CORE_PEER_MSPCONFIGPATH="+configtest.GetDevMspDir(), "CORE_PEER_LOCALMSPID=SampleOrg",
		"CORE_PEER_FILESYSTEMPATH="+filepath.Dir(ledgerRoot), "CORE_PEER_ADDRESS="+peerAddress,
		"CORE_LEDGER_SNAPSHOTS_ROOTDIR="+filepath.Join(root, "snapshots"),
		"CORE_PEER_LISTENADDRESS="+peerAddress, "CORE_PEER_ADDRESSAUTODETECT=false",
		"CORE_PEER_CHAINCODELISTENADDRESS="+ccAddress, "CORE_PEER_CHAINCODEADDRESS="+ccAddress,
		"CORE_PEER_TLS_ENABLED=true", "CORE_PEER_TLS_CLIENTAUTHREQUIRED=true",
		"CORE_PEER_TLS_CERT_FILE="+certFile, "CORE_PEER_TLS_KEY_FILE="+keyFile,
		"CORE_PEER_TLS_CLIENTCERT_FILE="+write("client.crt", clientKey.Cert), "CORE_PEER_TLS_CLIENTKEY_FILE="+write("client.key", clientKey.Key),
		"CORE_PEER_TLS_ROOTCERT_FILE="+caFile, "CORE_PEER_TLS_CLIENTROOTCAS_FILES="+caFile,
		"CORE_PEER_GOSSIP_USELEADERELECTION=false", "CORE_PEER_GOSSIP_ORGLEADER=false",
		"CORE_OPERATIONS_LISTENADDRESS="+operationsAddress, "CORE_OPERATIONS_TLS_ENABLED=true",
		"CORE_OPERATIONS_TLS_CERT_FILE="+certFile, "CORE_OPERATIONS_TLS_KEY_FILE="+keyFile,
		"CORE_OPERATIONS_TLS_CLIENTAUTHREQUIRED=true", "CORE_OPERATIONS_TLS_CLIENTROOTCAS_FILES="+caFile,
		"CORE_VM_ENDPOINT=unix:///var/run/docker.sock",
	)
	cert, err := tls.X509KeyPair(clientKey.Cert, clientKey.Key)
	require.NoError(t, err)
	certPool := x509.NewCertPool()
	require.True(t, certPool.AppendCertsFromPEM(rootCA.CertBytes()))
	tlsConfig := &tls.Config{
		RootCAs: certPool, Certificates: []tls.Certificate{cert}, ServerName: "127.0.0.1",
		MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
	}
	peerCLI := func(args ...string) string {
		ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, binary, args...)
		cmd.Env = env
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "%s", output)
		return string(output)
	}
	command := func() *exec.Cmd {
		cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestPQ40EManagedOrdererRestart$")
		cmd.Env = append(env, evidence...)
		return cmd
	}
	creator, err := fixture.Fabric.Serialize()
	require.NoError(t, err)
	query := func(client peerpb.EndorserClient, chaincode, function, headerChannel string) *peerpb.Response {
		t.Helper()
		proposal, _, err := protoutil.CreateChaincodeProposal(cb.HeaderType_ENDORSER_TRANSACTION, headerChannel, &peerpb.ChaincodeInvocationSpec{
			ChaincodeSpec: &peerpb.ChaincodeSpec{
				ChaincodeId: &peerpb.ChaincodeID{Name: chaincode},
				Input:       &peerpb.ChaincodeInput{Args: [][]byte{[]byte(function), []byte(testfixture.ChannelID)}},
			},
		}, creator)
		require.NoError(t, err)
		signed, err := protoutil.GetSignedProposal(proposal, fixture.Fabric)
		require.NoError(t, err)
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		result, err := client.ProcessProposal(ctx, signed)
		require.NoError(t, err)
		require.NotNil(t, result.GetResponse())
		return result.GetResponse()
	}
	base := testfixture.Config(t, genesis)
	candidate := fixture.Update(t, base)
	nextBlock := protoutil.NewBlock(1, protoutil.BlockHeaderHash(genesis.GetHeader()))
	nextBlock.Data.Data = [][]byte{protoutil.MarshalOrPanic(fixture.Envelope(t, candidate))}
	nextBlock.Header.DataHash = protoutil.ComputeBlockDataHash(nextBlock.GetData())
	interrupt := errors.New("test interrupted the transition before ledger commit")
	prepareTransition := func() activation.Channel {
		t.Helper()
		store, err := activation.OpenStore(state, nil)
		require.NoError(t, err)
		channel := fixture.Channel(store, activation.Ledger{
			LatestConfig: func() (*cb.Block, error) { return genesis, nil },
			Height:       func() (uint64, error) { return 1, nil },
			Block:        func(uint64) (*cb.Block, error) { return genesis, nil },
		})
		require.NoError(t, channel.Recover(true))
		return channel
	}
	requireManagedStartupRejected(t, command(), "CORE_OPERATIONS_TLS_ENABLED=false", "protected HTTP listener requires TLS")
	requireManagedStartupRejected(t, command(), "CORE_PEER_PROFILE_ENABLED=true", "forbids the profiling listener")
	for attempt := range 3 {
		cmd := command()
		log, err := os.CreateTemp(root, "peer-*.log")
		require.NoError(t, err)
		cmd.Stdout, cmd.Stderr = log, log
		require.NoError(t, cmd.Start())
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		t.Cleanup(func() {
			_ = cmd.Process.Kill()
			_ = log.Close()
			if t.Failed() {
				trace, _ := os.ReadFile(log.Name())
				t.Logf("managed peer log:\n%s", trace)
			}
		})
		require.Eventually(t, func() bool {
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", peerAddress, tlsConfig)
			if err != nil {
				return false
			}
			defer conn.Close()
			return conn.ConnectionState().CurveID == tls.X25519MLKEM768
		}, 15*time.Second, 100*time.Millisecond)
		verifyManagedOperations(t, operationsAddress, tlsConfig)
		if attempt == 0 {
			peerCLI("channel", "join", "-b", genesisPath)
		}
		conn, err := grpc.NewClient(peerAddress, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig.Clone())))
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })
		endorser := peerpb.NewEndorserClient(conn)
		if attempt < 2 {
			require.Contains(t, peerCLI("channel", "list"), testfixture.ChannelID)
			result := query(endorser, "qscc", qscc.GetChainInfo, testfixture.ChannelID)
			require.Equal(t, int32(200), result.GetStatus(), result.GetMessage())
			info := &cb.BlockchainInfo{}
			require.NoError(t, proto.Unmarshal(result.GetPayload(), info))
			require.Equal(t, uint64(1), info.GetHeight())
			result = query(endorser, "cscc", cscc.GetChannelConfig, "")
			require.Equal(t, int32(200), result.GetStatus(), result.GetMessage())
			config := &cb.Config{}
			require.NoError(t, proto.Unmarshal(result.GetPayload(), config))
			require.True(t, proto.Equal(base, config), "the interrupted candidate must stay unpublished")

			snapshotReq := protoutil.MarshalOrPanic(&peerpb.SnapshotRequest{
				SignatureHeader: &cb.SignatureHeader{Creator: creator}, ChannelId: testfixture.ChannelID,
			})
			signature, err := fixture.Fabric.Sign(snapshotReq)
			require.NoError(t, err)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			_, err = peerpb.NewSnapshotClient(conn).Generate(ctx, &peerpb.SignedSnapshotRequest{Request: snapshotReq, Signature: signature})
			cancel()
			require.Equal(t, codes.FailedPrecondition, status.Code(err), "%v", err)
		} else {
			require.NotContains(t, peerCLI("channel", "list"), testfixture.ChannelID)
			result := query(endorser, "cscc", cscc.GetChannelConfig, "")
			require.Equal(t, int32(503), result.GetStatus(), result.GetMessage())
			require.Contains(t, result.GetMessage(), "protected channel admission is closed")
			require.Empty(t, result.GetPayload())
			result = query(endorser, "qscc", qscc.GetChainInfo, "")
			require.Equal(t, int32(503), result.GetStatus(), result.GetMessage())
			require.Empty(t, result.GetPayload())
		}
		signal := syscall.SIGTERM
		if attempt == 0 {
			signal = syscall.SIGKILL
		}
		require.NoError(t, cmd.Process.Signal(signal))
		select {
		case err := <-done:
			if attempt == 0 {
				require.ErrorContains(t, err, "signal: killed")
			} else {
				require.NoError(t, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("managed peer did not stop")
		}
		switch attempt {
		case 0:
			channel := prepareTransition()
			approval := fixture.Authorize(t, 1, base, candidate.GetConfig())
			require.ErrorIs(t, channel.Apply(nextBlock, approval, func() error { return interrupt }), interrupt)
			require.False(t, channel.Ready())
		case 1:
			journal, err := os.ReadFile(filepath.Join(state, "journal"))
			require.NoError(t, err)
			var durable struct{ Phase string }
			require.NoError(t, json.Unmarshal(journal, &durable))
			require.Equal(t, "ABORTED", durable.Phase)
			// Build persistent quarantine through the native activation controller.
			channel := prepareTransition()
			err = channel.ApplyPeerConfig(nextBlock, func() error {
				t.Fatal("a transition without operator approval reached the ledger")
				return nil
			})
			require.ErrorContains(t, err, "load operator approval")
		}
	}
}

func requireManagedStartupRejected(t *testing.T, cmd *exec.Cmd, setting, reason string) {
	t.Helper()
	cmd.Env = append(cmd.Env, setting)
	output, err := cmd.CombinedOutput()
	require.Error(t, err)
	require.Contains(t, string(output), reason)
}

func verifyManagedOperations(t *testing.T, address string, config *tls.Config) {
	t.Helper()
	url := "https://" + address + "/version"
	transport := &http.Transport{TLSClientConfig: config.Clone()}
	defer transport.CloseIdleConnections()
	response, err := (&http.Client{Transport: transport, Timeout: time.Second}).Get(url)
	require.NoError(t, err)
	defer response.Body.Close()
	require.Equal(t, http.StatusOK, response.StatusCode)
	require.Equal(t, uint16(tls.VersionTLS13), response.TLS.Version)
	require.Equal(t, tls.X25519MLKEM768, response.TLS.CurveID)
	for _, tc := range []struct {
		name   string
		change func(*tls.Config)
	}{
		{"classical key exchange", func(cfg *tls.Config) { cfg.CurvePreferences = []tls.CurveID{tls.X25519} }},
		{"missing client identity", func(cfg *tls.Config) { cfg.Certificates = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			incompatible := transport.Clone()
			defer incompatible.CloseIdleConnections()
			tc.change(incompatible.TLSClientConfig)
			rejected, err := (&http.Client{Transport: incompatible, Timeout: time.Second}).Get(url)
			if rejected != nil {
				_ = rejected.Body.Close()
			}
			require.Error(t, err)
		})
	}
}

func managedGenesis(t *testing.T, fixture testfixture.Fixture, root, serverCert []byte, port string, transportCapability ...bool) *cb.Block {
	t.Helper()
	genesis := testfixture.Genesis(t)
	if len(transportCapability) != 0 && transportCapability[0] {
		genesis = testfixture.TransportGenesis(t)
	}
	config := testfixture.Config(t, genesis)
	delete(config.GetChannelGroup().GetGroups(), "Consortiums")
	ordererGroup := config.GetChannelGroup().GetGroups()["Orderer"]
	for _, group := range []*cb.ConfigGroup{ordererGroup, config.GetChannelGroup().GetGroups()["Application"]} {
		for _, org := range group.GetGroups() {
			msp := &mb.MSPConfig{}
			value := org.GetValues()["MSP"]
			require.NoError(t, proto.Unmarshal(value.GetValue(), msp))
			fabric := &mb.FabricMSPConfig{}
			require.NoError(t, proto.Unmarshal(msp.GetConfig(), fabric))
			fabric.TlsRootCerts = [][]byte{root}
			fabric.TlsIntermediateCerts = nil
			msp.Config = protoutil.MarshalOrPanic(fabric)
			value.Value = protoutil.MarshalOrPanic(msp)
		}
	}
	p, err := net.LookupPort("tcp", port)
	require.NoError(t, err)
	metadata := &pb.ConfigMetadata{
		Options:    &pb.Options{TickInterval: "50ms", HeartbeatTick: 1, ElectionTick: 5, MaxInflightBlocks: 4},
		Consenters: []*pb.Consenter{{Host: "127.0.0.1", Port: uint32(p), ClientTlsCert: serverCert, ServerTlsCert: serverCert}},
	}
	ordererGroup.GetValues()["ConsensusType"].Value = protoutil.MarshalOrPanic(&ab.ConsensusType{Type: "etcdraft", Metadata: protoutil.MarshalOrPanic(metadata)})
	_, err = channelconfig.NewBundle(testfixture.ChannelID, config, fixture.Crypto)
	require.NoError(t, err)
	envelope := fixture.Envelope(t, &cb.ConfigEnvelope{Config: config})
	genesis.Data.Data[0] = protoutil.MarshalOrPanic(envelope)
	genesis.Header.DataHash = protoutil.ComputeBlockDataHash(genesis.GetData())
	return genesis
}
