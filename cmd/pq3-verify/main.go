/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/hyperledger/fabric-lib-go/bccsp/factory"
	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-protos-go-apiv2/ledger/rwset"
	"github.com/hyperledger/fabric-protos-go-apiv2/ledger/rwset/kvrwset"
	mspprotos "github.com/hyperledger/fabric-protos-go-apiv2/msp"
	peer "github.com/hyperledger/fabric-protos-go-apiv2/peer"
	"github.com/hyperledger/fabric/common/channelconfig"
	"github.com/hyperledger/fabric/msp"
	"github.com/hyperledger/fabric/orderer/common/cluster"
	oqs "github.com/hyperledger/fabric/pq-crypto"
	"github.com/hyperledger/fabric/protoutil"
	"google.golang.org/protobuf/proto"
)

type result struct {
	ChannelID                  string   `json:"channel_id"`
	TxID                       string   `json:"tx_id"`
	BlockNumber                uint64   `json:"block_number"`
	BlockSignatureValid        bool     `json:"block_signature_valid"`
	HybridChannelRequired      bool     `json:"hybrid_channel_required"`
	TransactionStatusAvailable bool     `json:"transaction_status_available"`
	Org1ValidationCode         string   `json:"org1_validation_code"`
	Org2ValidationCode         string   `json:"org2_validation_code"`
	StateKey                   string   `json:"state_key"`
	StateValue                 string   `json:"state_value"`
	Org1State                  string   `json:"org1_state"`
	Org2State                  string   `json:"org2_state"`
	TransactionsChecked        int      `json:"transactions_checked"`
	VerifiedEndorsements       int      `json:"verified_endorsements"`
	VerifiedChaincode          string   `json:"verified_chaincode"`
	EndorsingMSPs              []string `json:"endorsing_msps"`
	HybridProfile              string   `json:"hybrid_profile"`
	ValidatedProfileOIDs       bool     `json:"validated_profile_oids"`
}

func main() {
	configPath := flag.String("config-block", "", "path to the channel config block")
	blockPath := flag.String("block", "", "path to the hex-encoded committed transaction block")
	chaincode := flag.String("require-chaincode", "", "require and verify a valid transaction for this chaincode")
	orgs := flag.String("require-orgs", "", "comma-separated MSP IDs required to endorse the requested chaincode")
	txID := flag.String("tx-id", "", "transaction ID to verify")
	org1ProcessedPath := flag.String("processed-transaction-org1", "", "path to Org1 QSCC GetTransactionByID hex output")
	org2ProcessedPath := flag.String("processed-transaction-org2", "", "path to Org2 QSCC GetTransactionByID hex output")
	stateKey := flag.String("require-state-key", "", "require this key in the transaction's endorsed write set")
	stateValue := flag.String("require-state-value", "", "required value in the transaction's endorsed write set")
	org1State := flag.String("org1-state", "", "state read from Org1 after commit")
	org2State := flag.String("org2-state", "", "state read from Org2 after commit")
	flag.Parse()
	if *configPath == "" || *blockPath == "" || *chaincode == "" || *orgs == "" ||
		*txID == "" || *org1ProcessedPath == "" || *org2ProcessedPath == "" ||
		*stateKey == "" || *stateValue == "" {
		fail(errors.New("--config-block, --block, --require-chaincode, --require-orgs, --tx-id, both processed-transaction files, and required state are required"))
	}
	if *org1State != *stateValue || *org2State != *stateValue {
		fail(fmt.Errorf("peer state does not match required committed value %q: Org1=%q Org2=%q",
			*stateValue, *org1State, *org2State))
	}

	if err := factory.InitFactories(nil); err != nil {
		fail(fmt.Errorf("initialize BCCSP: %w", err))
	}
	configBlock := readBlock(*configPath)
	block := readHexBlock(*blockPath)
	if configBlock.GetHeader().GetNumber() != 0 {
		fail(fmt.Errorf("config block number must be 0, got %d", configBlock.GetHeader().GetNumber()))
	}
	if err := verifyBlockDataHash(configBlock); err != nil {
		fail(fmt.Errorf("config block data hash: %w", err))
	}

	envelope, err := protoutil.ExtractEnvelope(configBlock, 0)
	if err != nil {
		fail(fmt.Errorf("extract channel config envelope: %w", err))
	}
	bundle, err := channelconfig.NewBundleFromEnvelope(envelope, factory.GetDefault())
	if err != nil {
		fail(fmt.Errorf("load channel MSP configuration: %w", err))
	}
	channelID, err := protoutil.GetChannelIDFromBlock(configBlock)
	if err != nil {
		fail(fmt.Errorf("read channel ID: %w", err))
	}
	profile, err := requiredProfileFromChannel(bundle.ChannelConfig().Capabilities())
	if err != nil {
		fail(err)
	}

	verifier := cluster.BlockVerifierBuilder(factory.GetDefault())(configBlock)
	if err := verifyBlockDataHash(block); err != nil {
		fail(fmt.Errorf("transaction block data hash: %w", err))
	}
	if block.GetHeader().GetNumber() == 0 {
		fail(errors.New("transaction block must not be the config block"))
	}
	if err := verifyBlockSignerProfiles(block, bundle.MSPManager(), profile); err != nil {
		fail(fmt.Errorf("validate orderer signer profile: %w", err))
	}
	if err := cluster.VerifyBlockSignature(block, verifier); err != nil {
		fail(fmt.Errorf("verify transaction block signature: %w", err))
	}

	targetEnvelope, targetIndex, err := findCommittedTransaction(block, *txID)
	if err != nil {
		fail(err)
	}
	org1ValidationCode := verifyProcessedTransaction(*org1ProcessedPath, *txID, targetEnvelope)
	org2ValidationCode := verifyProcessedTransaction(*org2ProcessedPath, *txID, targetEnvelope)
	requiredOrgs := splitSet(*orgs)
	if len(requiredOrgs) == 0 {
		fail(errors.New("--require-orgs must include at least one MSP ID"))
	}
	mspManager := bundle.MSPManager()
	verified := result{
		ChannelID:                  channelID,
		TxID:                       *txID,
		BlockNumber:                block.GetHeader().GetNumber(),
		BlockSignatureValid:        true,
		HybridChannelRequired:      true,
		TransactionStatusAvailable: true,
		Org1ValidationCode:         org1ValidationCode.String(),
		Org2ValidationCode:         org2ValidationCode.String(),
		StateKey:                   *stateKey,
		StateValue:                 *stateValue,
		Org1State:                  *org1State,
		Org2State:                  *org2State,
		HybridProfile:              profile.Name(),
		ValidatedProfileOIDs:       true,
	}
	for txIndex, rawEnvelope := range block.GetData().GetData() {
		if txIndex != targetIndex {
			continue
		}
		envelope := &cb.Envelope{}
		if err := proto.Unmarshal(rawEnvelope, envelope); err != nil {
			fail(fmt.Errorf("unmarshal transaction envelope %d: %w", txIndex, err))
		}
		payload, err := protoutil.UnmarshalPayload(envelope.GetPayload())
		if err != nil {
			fail(fmt.Errorf("unmarshal transaction payload %d: %w", txIndex, err))
		}
		if payload.GetHeader() == nil {
			fail(fmt.Errorf("transaction %d has no header", txIndex))
		}
		channelHeader, err := protoutil.UnmarshalChannelHeader(payload.GetHeader().GetChannelHeader())
		if err != nil {
			fail(fmt.Errorf("unmarshal transaction channel header %d: %w", txIndex, err))
		}
		if channelHeader.GetChannelId() != channelID {
			fail(fmt.Errorf("transaction %d belongs to channel %q, not %q", txIndex, channelHeader.GetChannelId(), channelID))
		}
		if channelHeader.GetTimestamp() == nil {
			fail(fmt.Errorf("transaction %d has no signed timestamp", txIndex))
		}
		if err := channelHeader.GetTimestamp().CheckValid(); err != nil {
			fail(fmt.Errorf("transaction %d has invalid timestamp: %w", txIndex, err))
		}
		signatureHeader, err := protoutil.UnmarshalSignatureHeader(payload.GetHeader().GetSignatureHeader())
		if err != nil {
			fail(fmt.Errorf("unmarshal transaction signature header %d: %w", txIndex, err))
		}
		creator, err := mspManager.DeserializeIdentity(signatureHeader.GetCreator())
		if err != nil {
			fail(fmt.Errorf("deserialize transaction creator %d: %w", txIndex, err))
		}
		creator, err = withTimestamp(creator, channelHeader.GetTimestamp().AsTime())
		if err != nil {
			fail(fmt.Errorf("bind transaction creator time %d: %w", txIndex, err))
		}
		if err := creator.Validate(); err != nil {
			fail(fmt.Errorf("validate transaction creator %d: %w", txIndex, err))
		}
		if err := verifySerializedIdentityProfile(signatureHeader.GetCreator(), profile); err != nil {
			fail(fmt.Errorf("verify transaction creator profile %d: %w", txIndex, err))
		}
		if err := creator.Verify(envelope.GetPayload(), envelope.GetSignature()); err != nil {
			fail(fmt.Errorf("verify client signature on transaction %d: %w", txIndex, err))
		}
		verified.TransactionsChecked++

		if cb.HeaderType(channelHeader.GetType()) != cb.HeaderType_ENDORSER_TRANSACTION {
			continue
		}
		transaction, err := protoutil.UnmarshalTransaction(payload.GetData())
		if err != nil {
			fail(fmt.Errorf("unmarshal transaction %d: %w", txIndex, err))
		}
		for _, action := range transaction.GetActions() {
			actionPayload, err := protoutil.UnmarshalChaincodeActionPayload(action.GetPayload())
			if err != nil {
				fail(fmt.Errorf("unmarshal chaincode action payload %d: %w", txIndex, err))
			}
			if actionPayload.GetAction() == nil {
				fail(fmt.Errorf("transaction %d has no endorsed action", txIndex))
			}
			responsePayload, err := protoutil.UnmarshalProposalResponsePayload(actionPayload.GetAction().GetProposalResponsePayload())
			if err != nil {
				fail(fmt.Errorf("unmarshal proposal response payload %d: %w", txIndex, err))
			}
			chaincodeAction := &peer.ChaincodeAction{}
			if err := proto.Unmarshal(responsePayload.GetExtension(), chaincodeAction); err != nil {
				fail(fmt.Errorf("unmarshal chaincode action %d: %w", txIndex, err))
			}
			if chaincodeAction.GetChaincodeId().GetName() == *chaincode {
				if err := verifyStateWrite(chaincodeAction.GetResults(), *chaincode, *stateKey, *stateValue); err != nil {
					fail(fmt.Errorf("transaction %s state write: %w", *txID, err))
				}
			}
			endorsingMSPs := make(map[string]struct{})
			for endorsementIndex, endorsement := range actionPayload.GetAction().GetEndorsements() {
				identity, err := mspManager.DeserializeIdentity(endorsement.GetEndorser())
				if err != nil {
					fail(fmt.Errorf("deserialize endorsement %d in transaction %d: %w", endorsementIndex, txIndex, err))
				}
				identity, err = withTimestamp(identity, channelHeader.GetTimestamp().AsTime())
				if err != nil {
					fail(fmt.Errorf("bind endorsement identity time %d in transaction %d: %w", endorsementIndex, txIndex, err))
				}
				if err := identity.Validate(); err != nil {
					fail(fmt.Errorf("validate endorsement %d in transaction %d: %w", endorsementIndex, txIndex, err))
				}
				if err := verifySerializedIdentityProfile(endorsement.GetEndorser(), profile); err != nil {
					fail(fmt.Errorf("verify endorsement profile %d in transaction %d: %w", endorsementIndex, txIndex, err))
				}
				roleBytes, err := proto.Marshal(&mspprotos.MSPRole{
					MspIdentifier: identity.GetMSPIdentifier(),
					Role:          mspprotos.MSPRole_PEER,
				})
				if err != nil {
					fail(fmt.Errorf("marshal peer role for endorsement %d in transaction %d: %w", endorsementIndex, txIndex, err))
				}
				if err := identity.SatisfiesPrincipal(&mspprotos.MSPPrincipal{
					PrincipalClassification: mspprotos.MSPPrincipal_ROLE,
					Principal:               roleBytes,
				}); err != nil {
					fail(fmt.Errorf("endorsement %d in transaction %d is not from a channel peer: %w", endorsementIndex, txIndex, err))
				}
				endorsementBytes := make([]byte, 0, len(actionPayload.GetAction().GetProposalResponsePayload())+len(endorsement.GetEndorser()))
				endorsementBytes = append(endorsementBytes, actionPayload.GetAction().GetProposalResponsePayload()...)
				endorsementBytes = append(endorsementBytes, endorsement.GetEndorser()...)
				if err := identity.Verify(endorsementBytes, endorsement.GetSignature()); err != nil {
					fail(fmt.Errorf("verify endorsement %d in transaction %d: %w", endorsementIndex, txIndex, err))
				}
				endorsingMSPs[identity.GetMSPIdentifier()] = struct{}{}
				verified.VerifiedEndorsements++
			}
			if chaincodeAction.GetChaincodeId().GetName() == *chaincode {
				creatorMSP := creator.GetMSPIdentifier()
				if creatorMSP != "Org1MSP" {
					fail(fmt.Errorf("required chaincode transaction was submitted by %s, expected Org1MSP", creatorMSP))
				}
				for required := range requiredOrgs {
					if _, exists := endorsingMSPs[required]; !exists {
						fail(fmt.Errorf("required chaincode transaction is missing endorsement from %s", required))
					}
				}
				verified.VerifiedChaincode = *chaincode
				for mspID := range endorsingMSPs {
					verified.EndorsingMSPs = append(verified.EndorsingMSPs, mspID)
				}
			}
		}
	}
	if verified.VerifiedChaincode == "" {
		fail(fmt.Errorf("block %d contains no valid %s transaction endorsed by %s",
			verified.BlockNumber, *chaincode, strings.Join(keys(requiredOrgs), ",")))
	}
	sort.Strings(verified.EndorsingMSPs)
	if err := json.NewEncoder(os.Stdout).Encode(verified); err != nil {
		fail(fmt.Errorf("encode evidence result: %w", err))
	}
}

func requiredProfileFromChannel(channelCapabilities channelconfig.ChannelCapabilities) (oqs.HybridCertificateProfile, error) {
	profileName := channelCapabilities.PactwayHybridCertificateProfile()
	if profileName == "" {
		return oqs.HybridCertificateProfile{}, errors.New("channel config does not require exactly one supported Pactway hybrid profile")
	}
	profile, err := oqs.HybridCertificateProfileByName(profileName, oqs.ProfileUseIsolatedDevelopment)
	if err != nil {
		return oqs.HybridCertificateProfile{}, fmt.Errorf("channel requires unsupported hybrid certificate profile %q: %w", profileName, err)
	}
	localProfile, err := oqs.HybridCertificateProfileFromEnvironment()
	if err != nil {
		return oqs.HybridCertificateProfile{}, err
	}
	if localProfile.Name() != profile.Name() {
		return oqs.HybridCertificateProfile{}, fmt.Errorf(
			"local profile %q does not match authenticated channel profile %q",
			localProfile.Name(),
			profile.Name(),
		)
	}
	return profile, nil
}

func verifyBlockSignerProfiles(block *cb.Block, manager msp.MSPManager, profile oqs.HybridCertificateProfile) error {
	signatureIndex := int(cb.BlockMetadataIndex_SIGNATURES)
	if block.GetMetadata() == nil || len(block.GetMetadata().GetMetadata()) <= signatureIndex {
		return errors.New("block has no signature metadata")
	}
	metadata := &cb.Metadata{}
	if err := proto.Unmarshal(block.GetMetadata().GetMetadata()[signatureIndex], metadata); err != nil {
		return fmt.Errorf("parse block signature metadata: %w", err)
	}
	if len(metadata.GetSignatures()) == 0 {
		return errors.New("block has no orderer signatures")
	}
	for index, signature := range metadata.GetSignatures() {
		signatureHeader, err := protoutil.UnmarshalSignatureHeader(signature.GetSignatureHeader())
		if err != nil {
			return fmt.Errorf("parse block signer %d header: %w", index, err)
		}
		identity, err := manager.DeserializeIdentity(signatureHeader.GetCreator())
		if err != nil {
			return fmt.Errorf("deserialize block signer %d: %w", index, err)
		}
		if err := identity.Validate(); err != nil {
			return fmt.Errorf("validate block signer %d identity: %w", index, err)
		}
		if err := verifySerializedIdentityProfile(signatureHeader.GetCreator(), profile); err != nil {
			return fmt.Errorf("verify block signer %d certificate profile: %w", index, err)
		}
	}
	return nil
}

func verifySerializedIdentityProfile(serialized []byte, profile oqs.HybridCertificateProfile) error {
	identity := &mspprotos.SerializedIdentity{}
	if err := proto.Unmarshal(serialized, identity); err != nil {
		return fmt.Errorf("parse serialized identity: %w", err)
	}
	block, _ := pem.Decode(identity.GetIdBytes())
	if block == nil {
		return errors.New("identity certificate is not PEM encoded")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse identity certificate: %w", err)
	}
	requiredOIDs := []asn1.ObjectIdentifier{profile.ProfileKeyOID(), profile.PQSignatureOID()}
	for _, requiredOID := range requiredOIDs {
		found := false
		for _, extension := range certificate.Extensions {
			if extension.Id.Equal(requiredOID) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("identity certificate is missing profile extension OID %s", requiredOID.String())
		}
	}
	return nil
}

func readBlock(path string) *cb.Block {
	raw, err := os.ReadFile(path)
	if err != nil {
		fail(fmt.Errorf("read block %s: %w", path, err))
	}
	block, err := protoutil.UnmarshalBlock(raw)
	if err != nil {
		fail(fmt.Errorf("parse block %s: %w", path, err))
	}
	return block
}

func readHexBlock(path string) *cb.Block {
	raw := readHex(path)
	block, err := protoutil.UnmarshalBlock(raw)
	if err != nil {
		fail(fmt.Errorf("parse hex-encoded block %s: %w", path, err))
	}
	return block
}

func readHex(path string) []byte {
	raw, err := os.ReadFile(path)
	if err != nil {
		fail(fmt.Errorf("read hex data %s: %w", path, err))
	}
	decoded, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		fail(fmt.Errorf("decode hex data %s: %w", path, err))
	}
	return decoded
}

func findCommittedTransaction(block *cb.Block, txID string) (*cb.Envelope, int, error) {
	if block.GetHeader() == nil || block.GetData() == nil || block.GetMetadata() == nil {
		return nil, -1, errors.New("committed block is missing header, data, or metadata")
	}
	filterIndex := int(cb.BlockMetadataIndex_TRANSACTIONS_FILTER)
	if len(block.GetMetadata().GetMetadata()) <= filterIndex {
		return nil, -1, errors.New("committed block has no transaction validation filter")
	}
	validationFlags := block.GetMetadata().GetMetadata()[filterIndex]
	if len(validationFlags) == 0 {
		return nil, -1, errors.New("committed block has no transaction validation filter")
	}
	if len(validationFlags) != len(block.GetData().GetData()) {
		return nil, -1, fmt.Errorf("transaction validation filter has %d entries for %d envelopes",
			len(validationFlags), len(block.GetData().GetData()))
	}
	matchingIndex := -1
	var matchingEnvelope *cb.Envelope
	for index, rawEnvelope := range block.GetData().GetData() {
		candidateTxID, err := protoutil.GetOrComputeTxIDFromEnvelope(rawEnvelope)
		if err != nil {
			return nil, -1, fmt.Errorf("read transaction ID at index %d: %w", index, err)
		}
		if candidateTxID != txID {
			continue
		}
		if matchingIndex >= 0 {
			return nil, -1, fmt.Errorf("transaction ID %s appears more than once in block %d", txID, block.GetHeader().GetNumber())
		}
		matchingEnvelope, err = protoutil.GetEnvelopeFromBlock(rawEnvelope)
		if err != nil {
			return nil, -1, fmt.Errorf("unmarshal transaction %s: %w", txID, err)
		}
		matchingIndex = index
	}
	if matchingIndex < 0 {
		return nil, -1, fmt.Errorf("transaction %s is not present in committed block %d", txID, block.GetHeader().GetNumber())
	}
	code := peer.TxValidationCode(validationFlags[matchingIndex])
	if code != peer.TxValidationCode_VALID {
		return nil, -1, fmt.Errorf("transaction %s has validation code %s in committed block", txID, code.String())
	}
	return matchingEnvelope, matchingIndex, nil
}

func verifyProcessedTransaction(path, txID string, expectedEnvelope *cb.Envelope) peer.TxValidationCode {
	raw := readHex(path)
	code, err := validateProcessedTransaction(raw, txID, expectedEnvelope)
	if err != nil {
		fail(fmt.Errorf("peer ledger transaction %s (%s): %w", txID, path, err))
	}
	return code
}

func validateProcessedTransaction(raw []byte, txID string, expectedEnvelope *cb.Envelope) (peer.TxValidationCode, error) {
	processed := &peer.ProcessedTransaction{}
	if err := proto.Unmarshal(raw, processed); err != nil {
		return peer.TxValidationCode_INVALID_OTHER_REASON, fmt.Errorf("parse processed transaction: %w", err)
	}
	code := peer.TxValidationCode(processed.GetValidationCode())
	if code != peer.TxValidationCode_VALID {
		return code, fmt.Errorf("has validation code %s", code.String())
	}
	if !proto.Equal(processed.GetTransactionEnvelope(), expectedEnvelope) {
		return code, errors.New("envelope does not match the committed block transaction")
	}
	envelopeBytes, err := proto.Marshal(processed.GetTransactionEnvelope())
	if err != nil {
		return code, fmt.Errorf("marshal envelope: %w", err)
	}
	processedTxID, err := protoutil.GetOrComputeTxIDFromEnvelope(envelopeBytes)
	if err != nil {
		return code, fmt.Errorf("read transaction ID: %w", err)
	}
	if processedTxID != txID {
		return code, fmt.Errorf("returned transaction %s, expected %s", processedTxID, txID)
	}
	return code, nil
}

func verifyStateWrite(results []byte, chaincode, key, value string) error {
	transactionRWSet := &rwset.TxReadWriteSet{}
	if err := proto.Unmarshal(results, transactionRWSet); err != nil {
		return fmt.Errorf("unmarshal endorsed read-write set: %w", err)
	}
	for _, namespaceRWSet := range transactionRWSet.GetNsRwset() {
		if namespaceRWSet.GetNamespace() != chaincode {
			continue
		}
		kvRWSet := &kvrwset.KVRWSet{}
		if err := proto.Unmarshal(namespaceRWSet.GetRwset(), kvRWSet); err != nil {
			return fmt.Errorf("unmarshal %s key-value read-write set: %w", chaincode, err)
		}
		for _, write := range kvRWSet.GetWrites() {
			if write.GetKey() == key && !write.GetIsDelete() && bytes.Equal(write.GetValue(), []byte(value)) {
				return nil
			}
		}
	}
	return fmt.Errorf("endorsed transaction does not write %q=%q in chaincode %s", key, value, chaincode)
}

func verifyBlockDataHash(block *cb.Block) error {
	if block.GetHeader() == nil || block.GetData() == nil || block.GetMetadata() == nil {
		return errors.New("block is missing header, data, or metadata")
	}
	hash, err := protoutil.BlockDataHash(block.GetData())
	if err != nil {
		return err
	}
	if !bytes.Equal(hash, block.GetHeader().GetDataHash()) {
		return errors.New("header data hash does not match block data")
	}
	return nil
}

func withTimestamp(identity msp.Identity, timestamp time.Time) (msp.Identity, error) {
	timeBound, ok := identity.(msp.TimeBoundIdentity)
	if !ok || !timeBound.RequiresTimeBoundValidation() {
		return identity, nil
	}
	return timeBound.WithValidationTime(&timestamp)
}

func splitSet(value string) map[string]struct{} {
	set := make(map[string]struct{})
	for entry := range strings.SplitSeq(value, ",") {
		entry = strings.TrimSpace(entry)
		if entry != "" {
			set[entry] = struct{}{}
		}
	}
	return set
}

func keys(set map[string]struct{}) []string {
	result := make([]string, 0, len(set))
	for key := range set {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
