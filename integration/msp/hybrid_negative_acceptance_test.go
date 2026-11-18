/*
Copyright IBM Corp All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package msp

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"syscall"

	"github.com/hyperledger/fabric-lib-go/bccsp/sw"
	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	peerprotos "github.com/hyperledger/fabric-protos-go-apiv2/peer"
	"github.com/hyperledger/fabric/common/capabilities"
	"github.com/hyperledger/fabric/integration/nwo"
	"github.com/hyperledger/fabric/integration/nwo/commands"
	"github.com/hyperledger/fabric/internal/configtxlator/update"
	oqs "github.com/hyperledger/fabric/pq-crypto"
	"github.com/hyperledger/fabric/protoutil"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/onsi/gomega/gexec"
	"github.com/tedsuo/ifrit"
	"google.golang.org/protobuf/proto"
)

var _ = Describe("Pactway hybrid network negative acceptance", func() {
	It("rejects invalid node identities and unsafe channel updates", func() {
		testDir, err := os.MkdirTemp("", "hybrid-negative-acceptance")
		Expect(err).NotTo(HaveOccurred())
		oldProfile, oldProfileSet := os.LookupEnv("PACTWAY_HYBRID_PROFILE")
		oldDevelopment, oldDevelopmentSet := os.LookupEnv("PACTWAY_ISOLATED_DEVELOPMENT")
		Expect(os.Setenv("PACTWAY_HYBRID_PROFILE", oqs.TemporaryHybridProfileV1)).To(Succeed())
		Expect(os.Setenv("PACTWAY_ISOLATED_DEVELOPMENT", "true")).To(Succeed())

		var network *nwo.Network
		var ordererProcess, peerProcess ifrit.Process
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
			restoreEnvironment("PACTWAY_HYBRID_PROFILE", oldProfile, oldProfileSet)
			restoreEnvironment("PACTWAY_ISOLATED_DEVELOPMENT", oldDevelopment, oldDevelopmentSet)
		})

		network = nwo.New(nwo.BasicEtcdRaft(), testDir, nil, StartPort(), components)
		ordererOrg := network.Organization("OrdererOrg")
		ordererOrg.MSPID = "OrdererOrgMSP"
		ordererOrg.EnableNodeOUs = true
		network.Profiles[0].ChannelCapabilities = []string{
			"V3_0",
			capabilities.PactwayHybridCertificateV1,
		}
		network.GenerateConfigTree()
		sess, err := network.Cryptogen(commands.Generate{
			Config: network.CryptoConfigPath(),
			Output: network.CryptoPath(),
		})
		Expect(err).NotTo(HaveOccurred())
		Eventually(sess, network.EventuallyTimeout).Should(gexec.Exit(0))

		configDir, err := filepath.Abs(filepath.Join("..", "..", "sampleconfig"))
		Expect(err).NotTo(HaveOccurred())
		hybridOutput := filepath.Join(testDir, "hybrid-profile")
		generateHybridNetwork(hybridOutput, configDir)
		installHybridNetworkMSPs(network, hybridOutput)
		for _, channel := range network.Channels {
			sess, err := network.ConfigTxGen(commands.OutputBlock{
				ChannelID: channel.Name, Profile: channel.Profile, ConfigPath: network.RootDir,
				OutputBlock: network.OutputBlockPath(channel.Name),
			})
			Expect(err).NotTo(HaveOccurred())
			Eventually(sess, network.EventuallyTimeout).Should(gexec.Exit(0))
		}
		network.ConcatenateTLSCACertificates()

		orderer := network.Orderer("orderer")
		org1Peer := network.Peer("Org1", "peer0")
		org2Peer := network.Peer("Org2", "peer0")
		ordererRunner, startedOrderer, startedPeers := network.StartSingleOrdererNetwork(orderer.Name)
		ordererProcess, peerProcess = startedOrderer, startedPeers
		nwo.JoinOrdererJoinPeersAppChannel(network, "testchannel", orderer, ordererRunner)

		validOrdererMSP := filepath.Join(testDir, "valid-orderer-msp")
		Expect(copyDirectory(network.OrdererLocalMSPDir(orderer), validOrdererMSP)).To(Succeed())
		stopOrderer := func() {
			ordererProcess.Signal(syscall.SIGTERM)
			Eventually(ordererProcess.Wait(), network.EventuallyTimeout).Should(Receive())
			ordererProcess = nil
		}
		startHealthyOrderer := func() {
			ordererRunner, ordererProcess = network.StartOrderer(orderer.Name)
		}
		expectOrdererRejection := func(identityMSP, profile, expectedLog string) {
			stopOrderer()
			if identityMSP != "" {
				Expect(installMSPKeepingTLS(identityMSP, network.OrdererLocalMSPDir(orderer))).To(Succeed())
			}

			oldProfileValue, oldProfileWasSet := os.LookupEnv("PACTWAY_HYBRID_PROFILE")
			if profile != "" {
				Expect(os.Setenv("PACTWAY_HYBRID_PROFILE", profile)).To(Succeed())
			}
			rejectedRunner := network.OrdererRunner(orderer)
			rejectedProcess := ifrit.Invoke(rejectedRunner)
			var exitErr error
			Eventually(rejectedProcess.Wait(), network.EventuallyTimeout).Should(Receive(&exitErr))
			Expect(exitErr).To(HaveOccurred())
			Expect(rejectedRunner.Err()).To(gbytes.Say(expectedLog))
			restoreEnvironment("PACTWAY_HYBRID_PROFILE", oldProfileValue, oldProfileWasSet)

			Expect(installMSPKeepingTLS(validOrdererMSP, network.OrdererLocalMSPDir(orderer))).To(Succeed())
			startHealthyOrderer()
		}

		ordererPrivate := filepath.Join(hybridOutput, "private", "organizations", "OrdererOrg")
		ordererAdminMSP := filepath.Join(ordererPrivate, "users", "Admin", "msp")
		expectOrdererRejection(
			"", "unsupported-pq3-profile", "unsupported hybrid certificate profile",
		)
		expectOrdererRejection(
			ordererAdminMSP, "", "does not satisfy channel ORDERER role",
		)

		missingPQMSP := filepath.Join(testDir, "missing-pq-key")
		Expect(copyDirectory(validOrdererMSP, missingPQMSP)).To(Succeed())
		Expect(removeHybridPrivateKey(missingPQMSP)).To(Succeed())
		expectOrdererRejection(
			missingPQMSP, "", "matching ML-DSA-65 private key",
		)

		currentConfig := nwo.GetConfig(network, org1Peer, orderer, "testchannel")
		unauthorizedConfig := proto.Clone(currentConfig).(*common.Config)
		org1Config := unauthorizedConfig.GetChannelGroup().GetGroups()["Application"].GetGroups()["Org1"]
		anchorPeers := &peerprotos.AnchorPeers{AnchorPeers: []*peerprotos.AnchorPeer{{
			Host: "peer0.org1.example.com",
			Port: 7051,
		}}}
		org1Config.GetValues()["AnchorPeers"] = &common.ConfigValue{
			Value:     protoutil.MarshalOrPanic(anchorPeers),
			ModPolicy: "Admins",
		}
		unauthorizedEnvelope := signHybridConfigUpdate(
			network, org1Peer, "User1", testDir, "unauthorized-update.pb",
			"testchannel", currentConfig, unauthorizedConfig,
		)
		nwo.UpdateWithStatus(network, orderer, "testchannel", unauthorizedEnvelope, http.StatusBadRequest, "policy")

		currentConfig = nwo.GetConfig(network, org1Peer, orderer, "testchannel")
		wrongOrganizationConfig := proto.Clone(currentConfig).(*common.Config)
		wrongOrganizationOrg1 := wrongOrganizationConfig.GetChannelGroup().GetGroups()["Application"].GetGroups()["Org1"]
		wrongOrganizationAnchorPeers := &peerprotos.AnchorPeers{AnchorPeers: []*peerprotos.AnchorPeer{{
			Host: "peer0.org1.example.com",
			Port: 7052,
		}}}
		wrongOrganizationOrg1.GetValues()["AnchorPeers"] = &common.ConfigValue{
			Value:     protoutil.MarshalOrPanic(wrongOrganizationAnchorPeers),
			ModPolicy: "Admins",
		}
		wrongOrganizationEnvelope := signHybridConfigUpdate(
			network, org2Peer, "Admin", testDir, "wrong-organization-update.pb",
			"testchannel", currentConfig, wrongOrganizationConfig,
		)
		nwo.UpdateWithStatus(
			network, orderer, "testchannel", wrongOrganizationEnvelope,
			http.StatusBadRequest, "policy",
		)

		currentConfig = nwo.GetConfig(network, org1Peer, orderer, "testchannel")
		capabilityRemoval := proto.Clone(currentConfig).(*common.Config)
		channelGroup := capabilityRemoval.GetChannelGroup()
		channelCapabilities := &common.Capabilities{}
		Expect(proto.Unmarshal(
			channelGroup.GetValues()["Capabilities"].GetValue(),
			channelCapabilities,
		)).To(Succeed())
		delete(
			channelCapabilities.GetCapabilities(),
			capabilities.PactwayHybridCertificateV1,
		)
		channelGroup.GetValues()["Capabilities"].Value = protoutil.MarshalOrPanic(channelCapabilities)
		capabilityEnvelope := signHybridConfigUpdate(
			network, org1Peer, "Admin", testDir, "remove-hybrid-capability.pb",
			"testchannel", currentConfig, capabilityRemoval, org2Peer,
		)
		capabilityFile := filepath.Join(testDir, "remove-hybrid-capability.pb")
		ordererSignature, err := network.OrdererAdminSession(
			orderer, org1Peer, commands.SignConfigTx{File: capabilityFile},
		)
		Expect(err).NotTo(HaveOccurred())
		Eventually(ordererSignature, network.EventuallyTimeout).Should(gexec.Exit(0))
		capabilityEnvelopeBytes, err := os.ReadFile(capabilityFile)
		Expect(err).NotTo(HaveOccurred())
		Expect(proto.Unmarshal(capabilityEnvelopeBytes, capabilityEnvelope)).To(Succeed())
		nwo.UpdateWithStatus(
			network, orderer, "testchannel", capabilityEnvelope, http.StatusBadRequest,
			"attempted to remove the required Pactway Hybrid Certificate v1 channel capability",
		)
	})
})

func removeHybridPrivateKey(mspDir string) error {
	certificatePEM, err := os.ReadFile(filepath.Join(mspDir, "signcerts", "cert.pem"))
	if err != nil {
		return err
	}
	block, _ := pem.Decode(certificatePEM)
	if block == nil {
		return os.ErrInvalid
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	profile, err := oqs.HybridCertificateProfileFromEnvironment()
	if err != nil {
		return err
	}
	hybridInfo, found, err := oqs.ParseHybridCertificate(certificate, profile)
	if err != nil {
		return err
	}
	if !found {
		return os.ErrInvalid
	}
	pqPublicKey, err := oqs.MarshalPKIXPublicKey(&hybridInfo.SubjectPublicKey)
	if err != nil {
		return err
	}
	keyStoreDir := filepath.Join(mspDir, "keystore")
	keyStore, err := sw.NewFileBasedKeyStore(nil, keyStoreDir, true)
	if err != nil {
		return err
	}
	csp, err := sw.NewDefaultSecurityLevelWithKeystore(keyStore)
	if err != nil {
		return err
	}
	pqPrivateKey := replayPrivateKey(csp, keyStoreDir, pqPublicKey)
	return os.Remove(filepath.Join(keyStoreDir, hex.EncodeToString(pqPrivateKey.SKI())+"_sk"))
}

func signHybridConfigUpdate(
	network *nwo.Network,
	signer *nwo.Peer,
	user, testDir, fileName, channel string,
	current, updated *common.Config,
	additionalSigners ...*nwo.Peer,
) *common.Envelope {
	configUpdate, err := update.Compute(current, updated)
	Expect(err).NotTo(HaveOccurred())
	configUpdate.ChannelId = channel
	envelope, err := protoutil.CreateSignedEnvelope(
		common.HeaderType_CONFIG_UPDATE,
		channel,
		nil,
		&common.ConfigUpdateEnvelope{ConfigUpdate: protoutil.MarshalOrPanic(configUpdate)},
		0,
		0,
	)
	Expect(err).NotTo(HaveOccurred())
	updateFile := filepath.Join(testDir, fileName)
	Expect(os.WriteFile(updateFile, protoutil.MarshalOrPanic(envelope), 0o600)).To(Succeed())
	signature, err := network.PeerUserSession(signer, user, commands.SignConfigTx{File: updateFile})
	Expect(err).NotTo(HaveOccurred())
	Eventually(signature, network.EventuallyTimeout).Should(gexec.Exit(0))
	for _, additionalSigner := range additionalSigners {
		signature, err = network.PeerUserSession(
			additionalSigner, "Admin", commands.SignConfigTx{File: updateFile},
		)
		Expect(err).NotTo(HaveOccurred())
		Eventually(signature, network.EventuallyTimeout).Should(gexec.Exit(0))
	}

	signedEnvelope := &common.Envelope{}
	envelopeBytes, err := os.ReadFile(updateFile)
	Expect(err).NotTo(HaveOccurred())
	Expect(proto.Unmarshal(envelopeBytes, signedEnvelope)).To(Succeed())
	return signedEnvelope
}
