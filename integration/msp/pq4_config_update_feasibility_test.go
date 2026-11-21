/*
Copyright IBM Corp All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package msp

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"syscall"

	commonproto "github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric/integration/nwo"
	"github.com/hyperledger/fabric/integration/nwo/commands"
	"github.com/hyperledger/fabric/protoutil"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/onsi/gomega/gexec"
	"github.com/tedsuo/ifrit"
	ginkgomon "github.com/tedsuo/ifrit/ginkgomon_v2"
	"google.golang.org/protobuf/proto"
)

var _ = Describe("PQ4 config update feasibility", func() {
	It("rejects stale updates but cannot detect restoration of an older orderer state", func() {
		testDir, err := os.MkdirTemp("", "pq4-config-update")
		Expect(err).NotTo(HaveOccurred())
		var network *nwo.Network
		var peerProcess, ordererProcess ifrit.Process
		DeferCleanup(func() {
			for _, process := range []ifrit.Process{peerProcess, ordererProcess} {
				if process != nil {
					process.Signal(syscall.SIGTERM)
					Eventually(process.Wait(), network.EventuallyTimeout).Should(Receive())
				}
			}
			if network != nil {
				network.Cleanup()
			}
			Expect(os.RemoveAll(testDir)).To(Succeed())
		})

		network = nwo.New(nwo.BasicEtcdRaft(), testDir, nil, StartPort(), components)
		network.Profiles[0].ChannelCapabilities = []string{"V3_0", "V2_0"}
		network.GenerateConfigTree()
		network.Bootstrap()
		orderer := network.Orderer("orderer")
		startOrderer := func() *ginkgomon.Runner {
			runner := network.OrdererRunner(orderer)
			ordererProcess = ifrit.Invoke(runner)
			Eventually(ordererProcess.Ready(), network.EventuallyTimeout).Should(BeClosed())
			return runner
		}
		stopOrderer := func() {
			ordererProcess.Signal(syscall.SIGTERM)
			Eventually(ordererProcess.Wait(), network.EventuallyTimeout).Should(Receive())
			ordererProcess = nil
		}
		ordererRunner := startOrderer()
		peerProcess = ifrit.Invoke(network.PeerGroupRunner())
		Eventually(peerProcess.Ready(), network.EventuallyTimeout).Should(BeClosed())
		nwo.JoinOrdererJoinPeersAppChannel(network, "testchannel", orderer, ordererRunner)

		org1 := network.Peer("Org1", "peer0")
		org2 := network.Peer("Org2", "peer0")
		current := nwo.GetConfig(network, org1, orderer, "testchannel")
		stopOrderer()
		ordererDir := network.OrdererDir(orderer)
		for _, name := range []string{"system", "etcdraft"} {
			Expect(copyDirectory(filepath.Join(ordererDir, name), filepath.Join(testDir, "snapshot", name))).To(Succeed())
		}
		ordererRunner = startOrderer()
		Eventually(ordererRunner.Err(), network.EventuallyTimeout).Should(
			gbytes.Say("Raft leader changed: .* -> 1 channel=testchannel node=1"),
		)
		updated := proto.Clone(current).(*commonproto.Config)
		capabilities := &commonproto.Capabilities{}
		value := updated.GetChannelGroup().GetValues()["Capabilities"]
		Expect(value).NotTo(BeNil())
		Expect(proto.Unmarshal(value.Value, capabilities)).To(Succeed())
		Expect(capabilities.Capabilities).To(HaveKey("V2_0"))
		Expect(capabilities.Capabilities).To(HaveKey("V3_0"))
		delete(capabilities.Capabilities, "V2_0")
		value.Value = protoutil.MarshalOrPanic(capabilities)

		unauthorized := signHybridConfigUpdate(network, org1, "User1", testDir, "unauthorized.pb", "testchannel", current, updated)
		nwo.UpdateWithStatus(network, orderer, "testchannel", unauthorized, http.StatusBadRequest, "policy for")
		Expect(proto.Equal(nwo.GetConfig(network, org1, orderer, "testchannel"), current)).To(BeTrue())

		const updateFile = "authorized.pb"
		authorized := signHybridConfigUpdate(network, org1, "Admin", testDir, updateFile, "testchannel", current, updated, org2)
		session, err := network.OrdererAdminSession(orderer, org1, commands.SignConfigTx{File: filepath.Join(testDir, updateFile)})
		Expect(err).NotTo(HaveOccurred())
		Eventually(session, network.EventuallyTimeout).Should(gexec.Exit(0))
		envelopeBytes, err := os.ReadFile(filepath.Join(testDir, updateFile))
		Expect(err).NotTo(HaveOccurred())
		Expect(proto.Unmarshal(envelopeBytes, authorized)).To(Succeed())
		nwo.Update(network, orderer, "testchannel", authorized)

		var committed *commonproto.Config
		Eventually(func() uint64 {
			committed = nwo.GetConfig(network, org1, orderer, "testchannel")
			return committed.GetSequence()
		}, network.EventuallyTimeout).Should(Equal(current.GetSequence() + 1))
		committedCapabilities := &commonproto.Capabilities{}
		committedValue := committed.GetChannelGroup().GetValues()["Capabilities"]
		Expect(proto.Unmarshal(committedValue.GetValue(), committedCapabilities)).To(Succeed())
		Expect(committedCapabilities.Capabilities).NotTo(HaveKey("V2_0"))
		Expect(committedCapabilities.Capabilities).To(HaveKey("V3_0"))
		Expect(committedValue.Version).To(Equal(value.Version + 1))

		replayError := fmt.Sprintf(
			"attempt to set key [Value]  /Channel/Capabilities to version %d, but key is at version %d",
			committedValue.Version, committedValue.Version,
		)
		nwo.UpdateWithStatus(network, orderer, "testchannel", authorized, http.StatusBadRequest, replayError)
		Expect(proto.Equal(nwo.GetConfig(network, org1, orderer, "testchannel"), committed)).To(BeTrue())

		peerProcess.Signal(syscall.SIGTERM)
		Eventually(peerProcess.Wait(), network.EventuallyTimeout).Should(Receive())
		peerProcess = nil
		stopOrderer()
		for _, name := range []string{"system", "etcdraft"} {
			Expect(os.Rename(filepath.Join(ordererDir, name), filepath.Join(testDir, "advanced-"+name))).To(Succeed())
			Expect(copyDirectory(filepath.Join(testDir, "snapshot", name), filepath.Join(ordererDir, name))).To(Succeed())
		}
		ordererRunner = startOrderer()
		Eventually(ordererRunner.Err(), network.EventuallyTimeout).Should(
			gbytes.Say("Raft leader changed: .* -> 1 channel=testchannel node=1"),
		)
		restored := nwo.GetConfig(network, org1, orderer, "testchannel")
		Expect(proto.Equal(restored, current)).To(BeTrue())
		restoredCapabilities := &commonproto.Capabilities{}
		Expect(proto.Unmarshal(restored.GetChannelGroup().GetValues()["Capabilities"].GetValue(), restoredCapabilities)).To(Succeed())
		Expect(restoredCapabilities.Capabilities).To(HaveKey("V2_0"))
		Expect(restoredCapabilities.Capabilities).To(HaveKey("V3_0"))
		nwo.Update(network, orderer, "testchannel", authorized)
		Eventually(func() bool {
			return proto.Equal(nwo.GetConfig(network, org1, orderer, "testchannel"), committed)
		}, network.EventuallyTimeout).Should(BeTrue())
	})
})
