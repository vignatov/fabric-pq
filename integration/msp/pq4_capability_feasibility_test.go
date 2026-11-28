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
		expectPQ4CapabilityPeerRejection(components.Peer(), experimentalPQ4Capability)
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
		expectPQ4CapabilityPeerRejection(peer, experimentalPQ4Capability)
		expectUnsupportedOrdererToRejectCapability(orderer, experimentalPQ4Capability)
	})
})

var _ = Describe("PQ4.0B.1 real capability compatibility", func() {
	for _, candidate := range []struct {
		name, peer, orderer, peerSHA, ordererSHA, revision string
	}{
		{"older Pactway", "PACTWAY_OLDER_PEER", "PACTWAY_OLDER_ORDERER", "PACTWAY_OLDER_PEER_SHA256", "PACTWAY_OLDER_ORDERER_SHA256", "PACTWAY_OLDER_REVISION"},
		{"upstream Fabric", "PACTWAY_UPSTREAM_PEER", "PACTWAY_UPSTREAM_ORDERER", "PACTWAY_UPSTREAM_PEER_SHA256", "PACTWAY_UPSTREAM_ORDERER_SHA256", "PACTWAY_UPSTREAM_PEER_REVISION"},
	} {
		It("rejects the real transport capability on "+candidate.name, func() {
			peer, orderer := os.Getenv(candidate.peer), os.Getenv(candidate.orderer)
			if peer == "" && orderer == "" {
				Skip("compatibility binaries are not configured")
			}
			verifyUnsupportedBinary(candidate.name+" peer", peer, candidate.peerSHA, candidate.revision)
			verifyUnsupportedBinary(candidate.name+" orderer", orderer, candidate.ordererSHA, candidate.revision)
			expectPQ4CapabilityPeerRejection(peer, "PactwayPQTransportV1")
			expectUnsupportedOrdererToRejectCapability(orderer, "PactwayPQTransportV1")
		})
	}
})

func expectPQ4CapabilityPeerRejection(binary, capability string) {
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
	network.Profiles[0].ChannelCapabilities = []string{"V3_0", capability}
	network.GenerateConfigTree()
	network.Bootstrap()
	expectUnsupportedPeerToRejectCapability(binary, capability, network, &peerProcess)
}
