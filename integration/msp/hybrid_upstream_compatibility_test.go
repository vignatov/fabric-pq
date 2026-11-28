/*
Copyright IBM Corp All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package msp

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/hyperledger/fabric/common/capabilities"
	"github.com/hyperledger/fabric/integration/nwo"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/onsi/gomega/gexec"
	"github.com/tedsuo/ifrit"
	ginkgomon "github.com/tedsuo/ifrit/ginkgomon_v2"
	"google.golang.org/protobuf/proto"
)

var _ = Describe("Upstream channel capability compatibility", func() {
	It("rejects temporary-profile channels with unmodified upstream Fabric", func() {
		upstreamPeer := os.Getenv("PACTWAY_UPSTREAM_PEER")
		if upstreamPeer == "" {
			Skip("set PACTWAY_UPSTREAM_PEER to a verified peer binary")
		}
		verifyUnsupportedBinary(
			"unmodified upstream Fabric peer",
			upstreamPeer,
			"PACTWAY_UPSTREAM_PEER_SHA256",
			"PACTWAY_UPSTREAM_PEER_REVISION",
		)

		testDir, err := os.MkdirTemp("", "upstream-channel-capability")
		Expect(err).NotTo(HaveOccurred())
		var network *nwo.Network
		var peerProcess ifrit.Process
		DeferCleanup(func() {
			if peerProcess != nil {
				peerProcess.Signal(syscall.SIGTERM)
				Eventually(peerProcess.Wait(), network.EventuallyTimeout).Should(Receive())
			}
			if network != nil {
				network.Cleanup()
			}
			Expect(os.RemoveAll(testDir)).To(Succeed())
		})

		network = nwo.New(nwo.BasicEtcdRaft(), testDir, nil, StartPort(), components)
		network.Profiles[0].ChannelCapabilities = []string{
			"V3_0",
			capabilities.PactwayHybridCertificateV1,
		}
		network.GenerateConfigTree()
		network.Bootstrap()

		expectUnsupportedPeerToRejectCapability(
			upstreamPeer,
			capabilities.PactwayHybridCertificateV1,
			network,
			&peerProcess,
		)
		_, err = GinkgoWriter.Write([]byte("PQ3_UPSTREAM_COMPATIBILITY_PASS\n"))
		Expect(err).NotTo(HaveOccurred())
	})
})

var _ = Describe("Permanent profile compatibility with unsupported binaries", func() {
	It("rejects permanent-profile channels with unsupported PQ2 and upstream binaries", func() {
		unsupportedPQ2Peer := os.Getenv("PACTWAY_UNSUPPORTED_PQ2_PEER")
		upstreamPeer := os.Getenv("PACTWAY_UPSTREAM_PEER")
		if unsupportedPQ2Peer == "" && upstreamPeer == "" {
			Skip("set PACTWAY_UNSUPPORTED_PQ2_PEER and PACTWAY_UPSTREAM_PEER to verified peer binaries")
		}
		if unsupportedPQ2Peer == "" || upstreamPeer == "" {
			Fail("both PACTWAY_UNSUPPORTED_PQ2_PEER and PACTWAY_UPSTREAM_PEER must name verified peer binaries")
		}

		testDir, err := os.MkdirTemp("", "upstream-channel-capability")
		Expect(err).NotTo(HaveOccurred())
		var network *nwo.Network
		var peerProcess ifrit.Process
		DeferCleanup(func() {
			if peerProcess != nil {
				peerProcess.Signal(syscall.SIGTERM)
				Eventually(peerProcess.Wait(), network.EventuallyTimeout).Should(Receive())
			}
			if network != nil {
				network.Cleanup()
			}
			Expect(os.RemoveAll(testDir)).To(Succeed())
		})

		network = nwo.New(nwo.BasicEtcdRaft(), testDir, nil, StartPort(), components)
		network.Profiles[0].ChannelCapabilities = []string{
			"V3_0",
			capabilities.PactwayHybridCertificatePactwayV1,
		}
		network.GenerateConfigTree()
		network.Bootstrap()

		for _, test := range []struct {
			name   string
			binary string
			shaEnv string
			revEnv string
		}{
			{
				name:   "unsupported PQ2",
				binary: unsupportedPQ2Peer,
				shaEnv: "PACTWAY_UNSUPPORTED_PQ2_PEER_SHA256",
				revEnv: "PACTWAY_UNSUPPORTED_PQ2_REVISION",
			},
			{
				name:   "unmodified upstream Fabric",
				binary: upstreamPeer,
				shaEnv: "PACTWAY_UPSTREAM_PEER_SHA256",
				revEnv: "PACTWAY_UPSTREAM_PEER_REVISION",
			},
		} {
			By("checking " + test.name)
			verifyUnsupportedBinary(test.name+" peer", test.binary, test.shaEnv, test.revEnv)
			expectUnsupportedPeerToRejectCapability(
				test.binary,
				capabilities.PactwayHybridCertificatePactwayV1,
				network,
				&peerProcess,
			)
		}
		_, err = GinkgoWriter.Write([]byte("PQ25_UNSUPPORTED_BINARY_COMPATIBILITY_PASS\n"))
		Expect(err).NotTo(HaveOccurred())
	})
})

var _ = Describe("Permanent profile orderer compatibility with unsupported binaries", func() {
	It("rejects permanent-profile channels and reports the capability in response and logs", func() {
		tests := []struct {
			name   string
			binary string
		}{
			{name: "pre-PQ2.5 Pactway orderer", binary: os.Getenv("PACTWAY_UNSUPPORTED_PQ2_ORDERER")},
			{name: "unmodified upstream Fabric orderer", binary: os.Getenv("PACTWAY_UPSTREAM_ORDERER")},
		}
		if tests[0].binary == "" && tests[1].binary == "" {
			Skip("set PACTWAY_UNSUPPORTED_PQ2_ORDERER and PACTWAY_UPSTREAM_ORDERER to verified orderer binaries")
		}
		if tests[0].binary == "" || tests[1].binary == "" {
			Fail("both PACTWAY_UNSUPPORTED_PQ2_ORDERER and PACTWAY_UPSTREAM_ORDERER must name verified binaries")
		}

		for _, test := range tests {
			By("checking " + test.name)
			shaEnv := "PACTWAY_UNSUPPORTED_PQ2_ORDERER_SHA256"
			revEnv := "PACTWAY_UNSUPPORTED_PQ2_REVISION"
			if strings.Contains(test.name, "upstream") {
				shaEnv = "PACTWAY_UPSTREAM_ORDERER_SHA256"
				revEnv = "PACTWAY_UPSTREAM_ORDERER_REVISION"
			}
			verifyUnsupportedBinary(test.name, test.binary, shaEnv, revEnv)
			expectUnsupportedOrdererToRejectCapability(
				test.binary,
				capabilities.PactwayHybridCertificatePactwayV1,
			)
		}
		_, err := GinkgoWriter.Write([]byte("PQ35_UNSUPPORTED_ORDERER_COMPATIBILITY_PASS\n"))
		Expect(err).NotTo(HaveOccurred())
	})
})

func verifyUnsupportedBinary(label, binary, shaEnv, revisionEnv string) {
	Expect(binary).NotTo(BeEmpty())
	expectedSHA := os.Getenv(shaEnv)
	Expect(expectedSHA).To(MatchRegexp(`^[[:xdigit:]]{64}$`), shaEnv)
	sourceRevision := os.Getenv(revisionEnv)
	Expect(sourceRevision).NotTo(BeEmpty(), revisionEnv)

	contents, err := os.ReadFile(binary)
	Expect(err).NotTo(HaveOccurred())
	digest := sha256.Sum256(contents)
	actualSHA := hex.EncodeToString(digest[:])
	Expect(actualSHA).To(Equal(expectedSHA), label+" SHA-256")

	versionOutput, err := exec.Command(binary, "version").CombinedOutput()
	Expect(err).NotTo(HaveOccurred(), string(versionOutput))
	Expect(string(versionOutput)).To(ContainSubstring("Version:"))
	_, err = fmt.Fprintf(
		GinkgoWriter,
		"PQ35_UNSUPPORTED_BINARY label=%q source_revision=%q version=%q sha256=%s\n",
		label,
		sourceRevision,
		strings.TrimSpace(string(versionOutput)),
		actualSHA,
	)
	Expect(err).NotTo(HaveOccurred())
}

func expectUnsupportedOrdererToRejectCapability(binary, requiredCapability string) {
	testDir, err := os.MkdirTemp("", "unsupported-orderer-channel-capability")
	Expect(err).NotTo(HaveOccurred())
	var network *nwo.Network
	var ordererProcess ifrit.Process
	defer func() {
		if ordererProcess != nil {
			ordererProcess.Signal(syscall.SIGTERM)
			var exitErr error
			Eventually(ordererProcess.Wait(), network.EventuallyTimeout).Should(Receive(&exitErr))
			_, writeErr := fmt.Fprintf(GinkgoWriter, "CAPABILITY_ORDERER process_exit=%v after=SIGTERM\n", exitErr)
			Expect(writeErr).NotTo(HaveOccurred())
		}
		if network != nil {
			network.Cleanup()
		}
		Expect(os.RemoveAll(testDir)).To(Succeed())
	}()

	network = nwo.New(nwo.BasicEtcdRaft(), testDir, nil, StartPort(), components)
	network.Profiles[0].ChannelCapabilities = []string{
		"V3_0",
		requiredCapability,
	}
	network.GenerateConfigTree()
	network.Bootstrap()
	orderer := network.Orderers[0]

	ordererCommand := exec.Command(binary, "start")
	ordererCommand.Env = append(os.Environ(),
		"FABRIC_CFG_PATH="+network.OrdererDir(orderer),
		"FABRIC_LOGGING_SPEC=debug",
		"ORDERER_GENERAL_BOOTSTRAPMETHOD=none",
		"ORDERER_CHANNELPARTICIPATION_ENABLED=true",
	)
	ordererRunner := ginkgomon.New(ginkgomon.Config{
		Name:              orderer.ID(),
		Command:           ordererCommand,
		StartCheck:        `Beginning to serve requests`,
		StartCheckTimeout: 15 * time.Second,
	})
	ordererProcess = ifrit.Invoke(ordererRunner)
	Eventually(ordererProcess.Ready(), network.EventuallyTimeout).Should(BeClosed())

	protocol := "http"
	if network.TLSEnabled {
		protocol = "https"
	}
	channelID := network.Channels[0].Name
	joinURL := fmt.Sprintf(
		"%s://127.0.0.1:%d/participation/v1/channels",
		protocol,
		network.OrdererPort(orderer, nwo.AdminPort),
	)
	blockBytes, err := proto.Marshal(network.LoadAppChannelGenesisBlock(channelID))
	Expect(err).NotTo(HaveOccurred())
	genesisDigest := sha256.Sum256(blockBytes)
	_, err = fmt.Fprintf(GinkgoWriter, "CAPABILITY_ORDERER binary=%q command=%q genesis_sha256=%x\n", binary, binary+" start", genesisDigest)
	Expect(err).NotTo(HaveOccurred())
	request := nwo.GenerateJoinRequest(joinURL, channelID, blockBytes)
	authClient, _ := nwo.OrdererOperationalClients(network, orderer)
	response, err := authClient.Do(request)
	Expect(err).NotTo(HaveOccurred())
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	Expect(err).NotTo(HaveOccurred())
	Expect(response.StatusCode).NotTo(Equal(http.StatusCreated))
	Expect(string(body)).To(ContainSubstring(fmt.Sprintf("Channel capability %s is required but not supported", requiredCapability)))
	_, err = fmt.Fprintf(GinkgoWriter, "CAPABILITY_ORDERER process_ready=true join_http_status=%d channel_ready=false diagnostic=%q\n", response.StatusCode, string(body))
	Expect(err).NotTo(HaveOccurred())
	Eventually(ordererRunner.Err(), network.EventuallyTimeout).Should(gbytes.Say(requiredCapability))
}

func expectUnsupportedPeerToRejectCapability(
	binary string,
	requiredCapability string,
	network *nwo.Network,
	peerProcess *ifrit.Process,
) {
	peer := network.Peer("Org1", "peer0")
	peerConfigPath := network.PeerDir(peer)
	peerRunner := ginkgomon.New(ginkgomon.Config{
		Name: peer.ID(),
		Command: &exec.Cmd{
			Path: binary,
			Args: []string{binary, "node", "start"},
			Env: append(os.Environ(),
				"FABRIC_CFG_PATH="+peerConfigPath,
				"CORE_LEDGER_STATE_COUCHDBCONFIG_USERNAME=admin",
				"CORE_LEDGER_STATE_COUCHDBCONFIG_PASSWORD=adminpw",
			),
		},
		StartCheck:        `Started peer with ID=.*`,
		StartCheckTimeout: 15 * time.Second,
	})
	*peerProcess = ifrit.Invoke(peerRunner)
	Eventually((*peerProcess).Ready(), network.EventuallyTimeout).Should(BeClosed())

	joinCommand := exec.Command(
		binary,
		"channel", "join",
		"-b", network.OutputBlockPath(network.Channels[0].Name),
	)
	joinCommand.Env = append(os.Environ(),
		"FABRIC_CFG_PATH="+peerConfigPath,
		"CORE_PEER_MSPCONFIGPATH="+network.PeerUserMSPDir(peer, "Admin"),
	)
	genesisBytes, err := os.ReadFile(network.OutputBlockPath(network.Channels[0].Name))
	Expect(err).NotTo(HaveOccurred())
	genesisDigest := sha256.Sum256(genesisBytes)
	_, err = fmt.Fprintf(GinkgoWriter, "CAPABILITY_PEER binary=%q command=%q genesis_sha256=%x\n", binary, strings.Join(joinCommand.Args, " "), genesisDigest)
	Expect(err).NotTo(HaveOccurred())
	session, err := gexec.Start(joinCommand, GinkgoWriter, GinkgoWriter)
	Expect(err).NotTo(HaveOccurred())
	Eventually(session, network.EventuallyTimeout).Should(gexec.Exit())
	Expect(session.ExitCode()).NotTo(Equal(0))
	output := strings.TrimSpace(string(session.Out.Contents()) + string(session.Err.Contents()))
	_, err = fmt.Fprintf(GinkgoWriter, "CAPABILITY_PEER join_exit_status=%d channel_ready=false diagnostic=%q\n", session.ExitCode(), output)
	Expect(err).NotTo(HaveOccurred())
	Expect(output).To(ContainSubstring(fmt.Sprintf("Channel capability %s is required but not supported", requiredCapability)))
	(*peerProcess).Signal(syscall.SIGTERM)
	Eventually((*peerProcess).Wait(), network.EventuallyTimeout).Should(Receive())
	*peerProcess = nil
}
