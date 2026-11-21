/*
Copyright IBM Corp All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package msp

import (
	"os"

	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric/common/capabilities"
	"github.com/hyperledger/fabric/integration/nwo"
	oqs "github.com/hyperledger/fabric/pq-crypto"
	. "github.com/onsi/gomega"
	"google.golang.org/protobuf/proto"
)

func selectedHybridAcceptanceProfile() (string, string) {
	profileName := os.Getenv("PACTWAY_HYBRID_PROFILE")
	if profileName == "" {
		profileName = oqs.TemporaryHybridProfileV1
	}
	profile, err := oqs.HybridCertificateProfileByName(
		profileName,
		oqs.ProfileUseIsolatedDevelopment,
	)
	Expect(err).NotTo(HaveOccurred())

	channelCapability, ok := map[string]string{
		oqs.TemporaryHybridProfileV1: capabilities.PactwayHybridCertificateV1,
		oqs.PermanentHybridProfileV1: capabilities.PactwayHybridCertificatePactwayV1,
	}[profile.Name()]
	Expect(ok).To(BeTrue(), "unsupported hybrid certificate profile %s", profile.Name())
	return profile.Name(), channelCapability
}

func expectHybridChannelCapability(
	network *nwo.Network,
	peer *nwo.Peer,
	orderer *nwo.Orderer,
	channelID string,
	expectedCapability string,
) {
	config := nwo.GetConfig(network, peer, orderer, channelID)
	channelCapabilitiesValue := config.GetChannelGroup().GetValues()["Capabilities"]
	Expect(channelCapabilitiesValue).NotTo(BeNil())

	channelCapabilities := &common.Capabilities{}
	Expect(proto.Unmarshal(channelCapabilitiesValue.GetValue(), channelCapabilities)).To(Succeed())
	Expect(channelCapabilities.GetCapabilities()).To(HaveKey(expectedCapability))

	for _, otherCapability := range []string{
		capabilities.PactwayHybridCertificateV1,
		capabilities.PactwayHybridCertificatePactwayV1,
	} {
		if otherCapability != expectedCapability {
			Expect(channelCapabilities.GetCapabilities()).NotTo(HaveKey(otherCapability))
		}
	}
}
