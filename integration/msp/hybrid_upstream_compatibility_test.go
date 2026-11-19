/*
Copyright IBM Corp All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package msp

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/hyperledger/fabric/common/capabilities"
	"github.com/hyperledger/fabric/integration/nwo"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gexec"
	"github.com/tedsuo/ifrit"
	ginkgomon "github.com/tedsuo/ifrit/ginkgomon_v2"
)

var _ = Describe("Upstream channel capability compatibility", func() {
	It("rejects temporary-profile channels with unmodified upstream Fabric", func() {
		upstreamPeer := os.Getenv("PACTWAY_UPSTREAM_PEER")
		if upstreamPeer == "" {
			Skip("set PACTWAY_UPSTREAM_PEER to a verified peer binary")
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
		}{
			{name: "unsupported PQ2", binary: unsupportedPQ2Peer},
			{name: "unmodified upstream Fabric", binary: upstreamPeer},
		} {
			By("checking " + test.name)
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
	session, err := gexec.Start(joinCommand, GinkgoWriter, GinkgoWriter)
	Expect(err).NotTo(HaveOccurred())
	Eventually(session, network.EventuallyTimeout).Should(gexec.Exit())
	Expect(session.ExitCode()).NotTo(Equal(0))
	output := strings.TrimSpace(string(session.Out.Contents()) + string(session.Err.Contents()))
	Expect(output).To(ContainSubstring(requiredCapability))
	(*peerProcess).Signal(syscall.SIGTERM)
	Eventually((*peerProcess).Wait(), network.EventuallyTimeout).Should(Receive())
	*peerProcess = nil
}
