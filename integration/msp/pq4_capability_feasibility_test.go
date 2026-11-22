/*
Copyright IBM Corp All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package msp

import (
	"os"
	"syscall"

	"github.com/hyperledger/fabric/integration/nwo"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/tedsuo/ifrit"
)

const experimentalPQ4Capability = "PactwayPQ4FeasibilityUnknownCapability"

var _ = Describe("PQ4 unknown capability feasibility", func() {
	It("rejects a channel carrying an experimental unknown capability on the baseline peer", func() {
		expectExperimentalPQ4CapabilityPeerRejection(components.Peer())
	})

	It("rejects a channel carrying an experimental unknown capability on the baseline orderer", func() {
		expectUnsupportedOrdererToRejectCapability(components.Orderer(), experimentalPQ4Capability)
	})

	It("rejects the experimental unknown capability on verified upstream peer and orderer binaries", func() {
		peer := os.Getenv("PACTWAY_UPSTREAM_PEER")
		orderer := os.Getenv("PACTWAY_UPSTREAM_ORDERER")
		if peer == "" && orderer == "" {
			Skip("set PACTWAY_UPSTREAM_PEER and PACTWAY_UPSTREAM_ORDERER to verified binaries")
		}
		Expect(peer).NotTo(BeEmpty(), "PACTWAY_UPSTREAM_PEER")
		Expect(orderer).NotTo(BeEmpty(), "PACTWAY_UPSTREAM_ORDERER")
		verifyUnsupportedBinary("upstream peer", peer, "PACTWAY_UPSTREAM_PEER_SHA256", "PACTWAY_UPSTREAM_PEER_REVISION")
		verifyUnsupportedBinary("upstream orderer", orderer, "PACTWAY_UPSTREAM_ORDERER_SHA256", "PACTWAY_UPSTREAM_ORDERER_REVISION")
		expectExperimentalPQ4CapabilityPeerRejection(peer)
		expectUnsupportedOrdererToRejectCapability(orderer, experimentalPQ4Capability)
	})
})

func expectExperimentalPQ4CapabilityPeerRejection(binary string) {
	testDir, err := os.MkdirTemp("", "pq4-unknown-capability-peer")
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
	network.Profiles[0].ChannelCapabilities = []string{"V3_0", experimentalPQ4Capability}
	network.GenerateConfigTree()
	network.Bootstrap()
	expectUnsupportedPeerToRejectCapability(binary, experimentalPQ4Capability, network, &peerProcess)
}
