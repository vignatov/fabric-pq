//go:build linux

/*
SPDX-License-Identifier: Apache-2.0
*/

package peer

import (
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	pb "github.com/hyperledger/fabric-protos-go-apiv2/peer"
	"github.com/hyperledger/fabric/common/ledger/testutil"
	"github.com/hyperledger/fabric/core/config/configtest"
	"github.com/hyperledger/fabric/core/ledger"
	"github.com/hyperledger/fabric/core/ledger/kvledger"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation/testfixture"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/enrollment"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/provisioning"
	"github.com/hyperledger/fabric/protoutil"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

const (
	provisioningVMEnv     = "PQ40E_PROVISIONING_VM"
	exporterChildEnv      = "PQ40E_CONTROLLED_EXPORTER"
	importerChildEnv      = "PQ40E_CONTROLLED_IMPORTER"
	authorizationFileEnv  = "PQ40E_AUTHORIZATION_FILE"
	authorityPublicKeyEnv = "PQ40E_AUTHORITY_PUBLIC_KEY"
	authorityIdentityEnv  = "PQ40E_AUTHORITY_IDENTITY"
	exporterPrivateKeyEnv = "PQ40E_EXPORTER_PRIVATE_KEY"
	exporterOverrideEnv   = "PQ40E_SOURCE_LEDGER_OVERRIDE"
	importRootEnv         = "PQ40E_IMPORT_ROOT"
	importSnapshotEnv     = "PQ40E_IMPORT_SNAPSHOT"
	importRecoveryEnv     = "PQ40E_IMPORT_RECOVERY"
	acceptanceRecordEnv   = "PQ40E_ACCEPTANCE_RECORD"
	manifestFileEnv       = "PQ40E_MANIFEST_FILE"
	historyFileEnv        = "PQ40E_HISTORY_FILE"
)

type provisioningAcceptanceEvidence struct {
	SchemaVersion            string   `json:"schema_version"`
	GitCommit                string   `json:"git_commit"`
	WorktreeClean            bool     `json:"worktree_clean"`
	CIWorkflow               string   `json:"ci_workflow"`
	CIJob                    string   `json:"ci_job"`
	CIRunID                  string   `json:"ci_run_id"`
	CIRunAttempt             string   `json:"ci_run_attempt"`
	ExporterBinarySHA256     string   `json:"exporter_binary_sha256"`
	ImporterBinarySHA256     string   `json:"importer_binary_sha256"`
	AuthorizationIdentity    string   `json:"authorization_identity"`
	AuthorizationDigest      string   `json:"authorization_digest"`
	ExporterOperationDigest  string   `json:"exporter_operation_digest"`
	ExporterIdentity         string   `json:"exporter_identity"`
	ExporterPublicKeySHA256  string   `json:"exporter_public_key_sha256"`
	SourceLedgerIdentity     string   `json:"source_ledger_identity"`
	SourceLedgerPath         string   `json:"source_ledger_path"`
	ControlledInvocation     []string `json:"controlled_invocation"`
	Channel                  string   `json:"channel"`
	TrustedGenesisIdentity   string   `json:"trusted_genesis_identity"`
	VerifiedHistoryIdentity  string   `json:"verified_history_identity"`
	ConfigurationSequence    uint64   `json:"configuration_sequence"`
	SnapshotBlockNumber      uint64   `json:"snapshot_block_number"`
	SnapshotBlockHash        string   `json:"snapshot_block_hash"`
	ConfigurationDigest      string   `json:"configuration_digest"`
	SignableMetadataDigest   string   `json:"signable_metadata_digest"`
	AdditionalMetadataDigest string   `json:"additional_metadata_digest"`
	ExporterEvidenceDigest   string   `json:"exporter_evidence_digest"`
	SnapshotInventoryDigest  string   `json:"snapshot_inventory_digest"`
	PeerJoinAnchorDigest     string   `json:"peer_join_anchor_digest"`
	ImportResult             string   `json:"import_result"`
	RecoveryResult           string   `json:"recovery_result"`
	BaselineLedgerContinuity string   `json:"baseline_ledger_continuity"`
}

// TestPQ40EControlledSnapshotProvisioning exercises authorization, native
// ledger selection, export, independent verification, approval and protected
// import across separate Linux identities on an explicitly enabled VM.
func TestPQ40EControlledSnapshotProvisioning(t *testing.T) {
	if os.Getenv(provisioningVMEnv) != "1" {
		t.Skip("requires an explicitly enabled disposable Linux VM")
	}
	require.Zero(t, os.Geteuid(), "run the provisioning acceptance as root on a disposable VM")

	run := func(name string, args ...string) string {
		t.Helper()
		output, err := exec.CommandContext(t.Context(), name, args...).CombinedOutput()
		require.NoError(t, err, "%s %s: %s", name, strings.Join(args, " "), output)
		return strings.TrimSpace(string(output))
	}
	identity := strconv.Itoa(os.Getpid())
	exporterUser := "pq4e-exp-" + identity
	importerUser := "pq4e-imp-" + identity
	run("useradd", "--system", "--user-group", "--shell", "/usr/sbin/nologin", exporterUser)
	run("useradd", "--system", "--user-group", "--shell", "/usr/sbin/nologin", importerUser)
	t.Cleanup(func() {
		_ = exec.Command("userdel", exporterUser).Run()
		_ = exec.Command("userdel", importerUser).Run()
	})
	exporterAccount, err := user.Lookup(exporterUser)
	require.NoError(t, err)
	importerAccount, err := user.Lookup(importerUser)
	require.NoError(t, err)
	exporterUID, err := strconv.Atoi(exporterAccount.Uid)
	require.NoError(t, err)
	exporterGID, err := strconv.Atoi(exporterAccount.Gid)
	require.NoError(t, err)
	importerUID, err := strconv.Atoi(importerAccount.Uid)
	require.NoError(t, err)
	importerGID, err := strconv.Atoi(importerAccount.Gid)
	require.NoError(t, err)

	// The separate users must traverse the workspace even when TMPDIR is private.
	workspace, err := os.MkdirTemp("/tmp", "pq40e3-provisioning-") //nolint:usetesting
	require.NoError(t, err)
	require.NoError(t, os.Chmod(workspace, 0o755))
	t.Cleanup(func() { _ = os.RemoveAll(workspace) })
	controlDir := filepath.Join(workspace, "authority")
	require.NoError(t, os.Mkdir(controlDir, 0o755))
	gopath := filepath.Join(workspace, "gopath")
	configParent := filepath.Join(gopath, "src", "github.com", "hyperledger", "fabric")
	require.NoError(t, os.MkdirAll(configParent, 0o755))
	run("cp", "-a", configtest.GetDevConfigDir(), filepath.Join(configParent, "sampleconfig"))
	exporterKeyDir := filepath.Join(workspace, "exporter-key")
	require.NoError(t, os.Mkdir(exporterKeyDir, 0o700))
	fixture := testfixture.New(t)
	genesis := fixture.RaftGenesis(t)
	update := fixture.Update(t, testfixture.Config(t, genesis))
	block := fixture.SignedBlock(t, genesis, fixture.Envelope(t, update), 1)
	block.Metadata.Metadata[cb.BlockMetadataIndex_TRANSACTIONS_FILTER] = []byte{byte(pb.TxValidationCode_VALID)}

	ledgerA := filepath.Join(workspace, "ledger-a")
	createControlledProvisioningLedger(t, ledgerA, testfixture.ChannelID, genesis, block)
	ledgerB := filepath.Join(workspace, "ledger-b")
	_, genesisB := testutil.NewBlockGenerator(t, "unapproved-ledger-b", false)
	createControlledProvisioningLedger(t, ledgerB, "unapproved-ledger-b", genesisB)
	require.NoError(t, os.Chmod(ledgerB, 0o700))

	peerRoot := filepath.Join(workspace, "importer-peer")
	stateDir := filepath.Join(peerRoot, "state")
	require.NoError(t, os.MkdirAll(stateDir, 0o700))
	store, err := activation.OpenStore(stateDir, nil)
	require.NoError(t, err)
	operatorSigner, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	configBytes, err := (proto.MarshalOptions{Deterministic: true}).Marshal(update.GetConfig())
	require.NoError(t, err)
	policyPayload, err := json.Marshal(pqtransport.Document{
		Network: testfixture.Network, Node: testfixture.Node, Version: 1, Profile: pqtransport.ProfileV1,
		Channels: map[string]pqtransport.ChannelBinding{
			testfixture.ChannelID: {Sequence: update.GetConfig().GetSequence(), Digest: hashBytes(configBytes)},
		},
	})
	require.NoError(t, err)
	policySignature, err := operatorSigner.Sign(rand.Reader, policyPayload, nil)
	require.NoError(t, err)
	require.NoError(t, store.Provision(pqtransport.Checkpoint{Version: 1, Digest: sha256.Sum256(policyPayload)}, policyPayload, policySignature))
	policyKeyPath := filepath.Join(controlDir, "policy-key")
	policyKey := operatorSigner.Public().(*mldsa.PublicKey).Bytes()
	require.NoError(t, os.WriteFile(policyKeyPath, policyKey, 0o444))
	policyKeyDigest := sha256.Sum256(policyKey)
	channelDigest := sha256.Sum256([]byte(testfixture.ChannelID))
	genesisPath := filepath.Join(stateDir, fmt.Sprintf("genesis-%x", channelDigest))
	genesisEncoded, err := json.Marshal(hex.EncodeToString(protoutil.BlockHeaderHash(genesis.GetHeader())))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(genesisPath, genesisEncoded, 0o444))
	require.NoError(t, os.WriteFile(genesisPath+".block", protoutil.MarshalOrPanic(genesis), 0o444))
	joinPath := filepath.Join(stateDir, fmt.Sprintf("join-peer-%x", channelDigest))
	require.NoError(t, os.WriteFile(joinPath+".block", protoutil.MarshalOrPanic(block), 0o444))
	authoritySigner, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	manifest := enrollment.Manifest{
		Mode: enrollment.Protected, Network: testfixture.Network, Node: testfixture.Node,
		Profile: pqtransport.ProfileV1, PolicySigner: policyKeyPath,
		PolicySignerDigest: hex.EncodeToString(policyKeyDigest[:]),
		StateDir:           stateDir, LedgerDir: filepath.Join(peerRoot, "ledgersData"),
		Generation: 1, Executable: filepath.Join(workspace, "pq40e3-peer.test"),
		SnapshotAuthority: "pq40e3-test-provisioner",
	}
	manifestPayload, err := json.Marshal(manifest)
	require.NoError(t, err)
	signedManifest, err := signProvisioningTestDocument(authoritySigner, "fabric-pq/enrollment/v1\x00", manifest)
	require.NoError(t, err)
	signedHistory, err := signProvisioningTestDocument(authoritySigner, "fabric-pq/enrollment-history/v1\x00", enrollment.History{
		Network: manifest.Network, Node: manifest.Node, Generation: manifest.Generation,
		ProtectedEver: true, ManifestDigest: hashBytes(manifestPayload),
	})
	require.NoError(t, err)
	verifiedManifest, err := enrollment.Verify(signedManifest, signedHistory, authoritySigner.Public().(*mldsa.PublicKey))
	require.NoError(t, err)
	registry, err := enrollment.OpenProtectedRegistry(verifiedManifest)
	require.NoError(t, err)
	verifiedHistory, err := provisioning.VerifyJoinHistory(
		registry, testfixture.ChannelID, []*cb.Block{genesis, block}, block.GetHeader().GetNumber(), fixture.Crypto,
	)
	require.NoError(t, err)
	report := verifiedHistory.Report()

	exporterSigner, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	authorityPrivateKeyPath := filepath.Join(controlDir, "authority.key")
	require.NoError(t, os.WriteFile(authorityPrivateKeyPath, authoritySigner.Bytes(), 0o400))
	operatorPrivateKeyPath := filepath.Join(controlDir, "operator.key")
	require.NoError(t, os.WriteFile(operatorPrivateKeyPath, operatorSigner.Bytes(), 0o400))
	authorityPublicKeyPath := filepath.Join(controlDir, "authority.pub")
	require.NoError(t, os.WriteFile(authorityPublicKeyPath, authoritySigner.Public().(*mldsa.PublicKey).Bytes(), 0o444))
	manifestPath := filepath.Join(controlDir, "manifest.json")
	historyPath := filepath.Join(controlDir, "history.json")
	require.NoError(t, os.WriteFile(manifestPath, signedManifest, 0o444))
	require.NoError(t, os.WriteFile(historyPath, signedHistory, 0o444))
	testBinary, err := copyTestBinary(t, workspace)
	require.NoError(t, err)
	binaryHash := hashFile(t, testBinary)
	authorization := provisioning.ExporterAuthorization{
		AuthorityIdentity:     "pq40e3-test-provisioner",
		Generation:            1,
		Network:               testfixture.Network,
		Channel:               testfixture.ChannelID,
		ExporterIdentity:      "pq40e3-exporter-a",
		ExporterPublicKey:     exporterSigner.Public().(*mldsa.PublicKey).Bytes(),
		SourceLedgerIdentity:  "ledger-a",
		SourceLedgerPath:      ledgerA,
		ExecutablePath:        testBinary,
		ExecutableSHA256:      binaryHash,
		TrustedGenesis:        report.TrustedGenesisBlockIdentity,
		ConfigurationSequence: report.TargetConfigurationSequence,
		ConfigurationDigest:   report.TargetConfigurationDigest,
		SnapshotBlockNumber:   report.TargetBlockNumber,
		SnapshotBlockHash:     report.TargetBlockHash,
		SourceHistoryIdentity: report.SourceHistoryIdentity,
		TransportProfile:      pqtransport.ProfileV1,
	}
	authorizationBytes, err := provisioning.SignExporterAuthorization(authorization, authoritySigner)
	require.NoError(t, err)
	verifiedAuthorization, err := provisioning.VerifyExporterAuthorization(
		authorizationBytes, manifest.SnapshotAuthority, authoritySigner.Public().(*mldsa.PublicKey),
	)
	require.NoError(t, err)
	authorization = verifiedAuthorization.Authorization()
	authorizationPath := filepath.Join(controlDir, "exporter-authorization.json")
	require.NoError(t, os.WriteFile(authorizationPath, authorizationBytes, 0o444))
	exporterPrivateKeyPath := filepath.Join(exporterKeyDir, "exporter.key")
	require.NoError(t, os.WriteFile(exporterPrivateKeyPath, exporterSigner.Bytes(), 0o400))
	operationPath := filepath.Join(controlDir, "operation.json")

	run("chown", "-R", fmt.Sprintf("%d:%d", exporterUID, exporterGID), ledgerA, exporterKeyDir)
	run("chown", "-R", fmt.Sprintf("%d:%d", importerUID, importerGID), peerRoot)
	// Runtime state is writable, but sticky-bit ownership protects provisioned anchors.
	run("chown", fmt.Sprintf("0:%d", importerGID), peerRoot, stateDir)
	for _, path := range []string{genesisPath, genesisPath + ".block", joinPath + ".block"} {
		run("chown", "0:0", path)
	}
	require.NoError(t, os.Chmod(stateDir, os.ModeSticky|0o770))
	require.NoError(t, os.Chmod(peerRoot, os.ModeSticky|0o770))
	require.NoError(t, os.Chmod(ledgerA, 0o700))
	require.NoError(t, os.Chmod(exporterKeyDir, 0o700))

	runAs := func(account string, variables map[string]string, testName string) (string, error) {
		t.Helper()
		args := []string{"-u", account, "--", testBinary, "-test.v", "-test.run=^" + testName + "$"}
		command := exec.CommandContext(t.Context(), "runuser", args...)
		command.Dir = workspace
		command.Env = os.Environ()
		command.Env = append(command.Env, "GOPATH="+gopath)
		for name, value := range variables {
			command.Env = append(command.Env, name+"="+value)
		}
		output, err := command.CombinedOutput()
		return string(output), err
	}
	commonExporterEnv := map[string]string{
		exporterChildEnv:      "1",
		authorizationFileEnv:  authorizationPath,
		authorityPublicKeyEnv: authorityPublicKeyPath,
		authorityIdentityEnv:  "pq40e3-test-provisioner",
		exporterPrivateKeyEnv: exporterPrivateKeyPath,
	}
	rejected, err := runAs(exporterUser, withEnvironment(commonExporterEnv, exporterOverrideEnv, ledgerB), "TestPQ40EControlledSnapshotExporterChild")
	require.Error(t, err)
	require.Contains(t, rejected, "unauthorized source-ledger override")
	require.Error(t, exec.Command("runuser", "-u", exporterUser, "--", "test", "-r", ledgerB).Run(),
		"exporter must not be able to read an unapproved ledger path")
	require.Error(t, exec.Command("runuser", "-u", exporterUser, "--", "test", "-w", authorizationPath).Run(),
		"exporter must not be able to rewrite authorization")
	require.Error(t, exec.Command("runuser", "-u", exporterUser, "--", "test", "-w", controlDir).Run(),
		"exporter must not be able to replace provisioner-controlled records")
	require.Error(t, exec.Command("runuser", "-u", exporterUser, "--", "test", "-r", operatorPrivateKeyPath).Run(),
		"exporter must not be able to read the operator signing key")
	require.Error(t, exec.Command("runuser", "-u", exporterUser, "--", "test", "-r", authorityPrivateKeyPath).Run(),
		"exporter must not be able to read the provisioning authority key")
	require.Error(t, exec.Command("runuser", "-u", importerUser, "--", "test", "-w", authorizationPath).Run(),
		"importer must not be able to replace exporter authorization")
	require.Error(t, exec.Command("runuser", "-u", importerUser, "--", "test", "-w", controlDir).Run(),
		"importer must not be able to replace provisioner-controlled records")
	require.Error(t, exec.Command("runuser", "-u", importerUser, "--", "test", "-r", authorityPrivateKeyPath).Run(),
		"importer must not be able to read the provisioning authority key")
	require.Error(t, exec.Command("runuser", "-u", importerUser, "--", "test", "-r", operatorPrivateKeyPath).Run(),
		"importer must not be able to read the operator signing key")
	require.Error(t, exec.Command("runuser", "-u", importerUser, "--", "test", "-r", exporterPrivateKeyPath).Run(),
		"importer must not be able to read the exporter signing key")

	exportOutput, err := runAs(exporterUser, commonExporterEnv, "TestPQ40EControlledSnapshotExporterChild")
	require.NoError(t, err, exportOutput)
	require.Equal(t, binaryHash, hashFile(t, testBinary))
	require.NoFileExists(t, joinPath, "a rejected source selection must not produce an approval")
	snapshotDir := kvledger.SnapshotDirForLedgerBlockNum(filepath.Join(ledgerA, "snapshots"), testfixture.ChannelID, report.TargetBlockNumber)
	require.DirExists(t, snapshotDir)
	expectedInvocation := []string{testBinary, "-test.v", "-test.run=^TestPQ40EControlledSnapshotExporterChild$"}
	evidencePath := filepath.Join(snapshotDir, enrollment.SnapshotExportEvidenceFileName)
	exportEvidence, err := os.ReadFile(evidencePath)
	require.NoError(t, err)
	operation := provisioning.ExporterExecution{
		AuthorizationDigest:  hashBytes(authorizationBytes),
		ApprovalIdentity:     authorization.ApprovalIdentity,
		Generation:           authorization.Generation,
		SourceLedgerIdentity: authorization.SourceLedgerIdentity,
		SourceLedgerPath:     authorization.SourceLedgerPath,
		Channel:              authorization.Channel,
		SnapshotBlockNumber:  authorization.SnapshotBlockNumber,
		SnapshotBlockHash:    authorization.SnapshotBlockHash,
		ExecutablePath:       testBinary,
		ExecutableSHA256:     binaryHash,
		ExportEvidenceDigest: hashBytes(exportEvidence),
		Launcher:             []string{"runuser", "-u", exporterUser, "--"},
		Invocation:           expectedInvocation,
		Result:               "success",
	}
	operationBytes, err := provisioning.SignExporterExecution(verifiedAuthorization, operation, authoritySigner)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(operationPath, operationBytes, 0o444))
	persistedOperationBytes, err := os.ReadFile(operationPath)
	require.NoError(t, err)
	verifiedExecution, err := provisioning.VerifyExporterExecution(verifiedAuthorization, persistedOperationBytes)
	require.NoError(t, err)

	attackerSigner, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	attackerAuthorization := authorization
	attackerAuthorization.ExporterIdentity = "self-authorized-exporter"
	attackerAuthorization.ExporterPublicKey = attackerSigner.Public().(*mldsa.PublicKey).Bytes()
	attackerBytes, err := provisioning.SignExporterAuthorization(attackerAuthorization, operatorSigner)
	require.NoError(t, err)
	_, err = provisioning.VerifyExporterAuthorization(
		attackerBytes,
		"pq40e3-test-provisioner",
		authoritySigner.Public().(*mldsa.PublicKey),
	)
	require.ErrorContains(t, err, "signature is invalid")
	selfVerifiedAuthorization, err := provisioning.VerifyExporterAuthorization(
		attackerBytes, "pq40e3-test-provisioner", operatorSigner.Public().(*mldsa.PublicKey),
	)
	require.NoError(t, err)
	_, err = selfVerifiedAuthorization.SnapshotExporterTrust(verifiedHistory)
	require.ErrorContains(t, err, "independently enrolled authority")
	wrongBoundary := authorization
	wrongBoundary.SnapshotBlockNumber++
	wrongBoundaryBytes, err := provisioning.SignExporterAuthorization(wrongBoundary, authoritySigner)
	require.NoError(t, err)
	wrongBoundaryAuthorization, err := provisioning.VerifyExporterAuthorization(
		wrongBoundaryBytes,
		"pq40e3-test-provisioner",
		authoritySigner.Public().(*mldsa.PublicKey),
	)
	require.NoError(t, err)
	_, err = wrongBoundaryAuthorization.SnapshotExporterTrust(verifiedHistory)
	require.ErrorContains(t, err, "conflicts with registry-bound Fabric history")

	exporterTrust, err := verifiedAuthorization.SnapshotExporterTrust(verifiedHistory)
	require.NoError(t, err)
	attackerPackage := filepath.Join(workspace, "self-authorized-package")
	copySnapshotPackage(t, snapshotDir, attackerPackage)
	require.NoError(t, os.Remove(filepath.Join(attackerPackage, enrollment.SnapshotExportEvidenceFileName)))
	attackerEvidence, err := provisioning.SignSnapshotExportEvidence(
		attackerPackage,
		provisioning.SnapshotExportClaims{
			Network: testfixture.Network, Channel: testfixture.ChannelID,
			ExporterIdentity:      "self-authorized-exporter",
			SourceLedgerIdentity:  authorization.SourceLedgerIdentity,
			GenesisIdentity:       authorization.TrustedGenesis,
			SnapshotBlockNumber:   authorization.SnapshotBlockNumber,
			SnapshotBlockHash:     authorization.SnapshotBlockHash,
			ConfigurationSequence: authorization.ConfigurationSequence,
			ConfigurationDigest:   authorization.ConfigurationDigest,
			SourceHistoryIdentity: authorization.SourceHistoryIdentity,
			TransportProfile:      authorization.TransportProfile,
		},
		attackerSigner,
	)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(attackerPackage, enrollment.SnapshotExportEvidenceFileName), attackerEvidence, 0o600))
	_, err = provisioning.VerifySnapshotExport(verifiedHistory, attackerPackage, exporterTrust)
	require.Error(t, err, "internally consistent evidence signed by an unapproved key must be rejected")
	selfChosenTrust, err := provisioning.NewSnapshotExporterTrust("self-authorized-exporter", authorization.SourceLedgerIdentity, attackerSigner.Public().(*mldsa.PublicKey))
	require.NoError(t, err)
	legacyExport, err := provisioning.VerifySnapshotExport(verifiedHistory, attackerPackage, selfChosenTrust)
	require.NoError(t, err)
	_, err = provisioning.SignVerifiedPeerSnapshotAnchor(verifiedHistory, legacyExport, nil, nil, operatorSigner)
	require.Error(t, err, "a caller with the operator key cannot approve an unauthorized exporter")
	_, err = provisioning.SignVerifiedPeerSnapshotAnchor(verifiedHistory, legacyExport, verifiedAuthorization, verifiedExecution, operatorSigner)
	require.ErrorContains(t, err, "conflicts with independent authorization")
	require.NoError(t, legacyExport.Close())
	_, err = provisioning.VerifyExporterExecution(verifiedAuthorization, nil)
	require.Error(t, err)
	rejectedOperation := operation
	rejectedOperation.Result = "rejected"
	_, err = provisioning.SignExporterExecution(verifiedAuthorization, rejectedOperation, authoritySigner)
	require.ErrorContains(t, err, "controlled execution conflicts")
	rejectedOperation = operation
	rejectedOperation.SourceLedgerPath = ledgerB
	_, err = provisioning.SignExporterExecution(verifiedAuthorization, rejectedOperation, authoritySigner)
	require.ErrorContains(t, err, "controlled execution conflicts")
	export, err := provisioning.VerifySnapshotExport(verifiedHistory, snapshotDir, exporterTrust)
	require.NoError(t, err)
	defer func() { require.NoError(t, export.Close()) }()
	tamper := exec.CommandContext(t.Context(), "runuser", "-u", exporterUser, "--", "/bin/sh", "-c",
		`chmod u+w "$1" && printf x >> "$1"`, "sh", evidencePath)
	tamperOutput, err := tamper.CombinedOutput()
	require.NoError(t, err, string(tamperOutput))
	stagedEvidence, err := os.ReadFile(filepath.Join(export.Directory(), enrollment.SnapshotExportEvidenceFileName))
	require.NoError(t, err)
	replacedEvidence, err := os.ReadFile(evidencePath)
	require.NoError(t, err)
	require.NotEqual(t, hashBytes(stagedEvidence), hashBytes(replacedEvidence))
	anchor, err := provisioning.SignVerifiedPeerSnapshotAnchor(verifiedHistory, export, verifiedAuthorization, verifiedExecution, operatorSigner)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(joinPath, anchor, 0o444))

	importSnapshot := filepath.Join(peerRoot, "approved-snapshot")
	copySnapshotPackage(t, export.Directory(), importSnapshot)
	run("chown", "-R", fmt.Sprintf("%d:%d", importerUID, importerGID), importSnapshot)
	for _, path := range []string{policyKeyPath, authorityPublicKeyPath, manifestPath, historyPath, joinPath, genesisPath} {
		output, err := exec.Command("runuser", "-u", importerUser, "--", "chmod", "u+w", path).CombinedOutput()
		require.Errorf(t, err, "importer must not chmod %s: %s", path, output)
		output, err = exec.Command("runuser", "-u", importerUser, "--", "rm", "-f", path).CombinedOutput()
		require.Errorf(t, err, "importer must not replace %s: %s", path, output)
		require.FileExists(t, path)
	}
	output, err := exec.Command("runuser", "-u", importerUser, "--", "mv", stateDir, stateDir+"-replaced").CombinedOutput()
	require.Errorf(t, err, "importer must not replace the protected state directory: %s", output)
	require.DirExists(t, stateDir)

	importerEnv := map[string]string{
		importerChildEnv:      "1",
		importRootEnv:         peerRoot,
		importSnapshotEnv:     importSnapshot,
		acceptanceRecordEnv:   filepath.Join(peerRoot, "acceptance.json"),
		manifestFileEnv:       manifestPath,
		historyFileEnv:        historyPath,
		authorityPublicKeyEnv: authorityPublicKeyPath,
	}
	var anchorEnvelope enrollment.Envelope
	require.NoError(t, json.Unmarshal(anchor, &anchorEnvelope))
	var peerAnchor enrollment.PeerSnapshotAnchor
	require.NoError(t, json.Unmarshal(anchorEnvelope.Payload, &peerAnchor))
	peerAnchor.ExporterPublicKey = attackerSigner.Public().(*mldsa.PublicKey).Bytes()
	peerAnchor.ExporterIdentity = "self-authorized-exporter"
	peerAnchor.ExportEvidenceHash = hashBytes(attackerEvidence)
	attackerAnchor, err := signProvisioningTestAnchor(t, operatorSigner, peerAnchor)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(joinPath, attackerAnchor, 0o400))
	importerAttackerPackage := filepath.Join(peerRoot, "unauthorized-snapshot")
	copySnapshotPackage(t, attackerPackage, importerAttackerPackage)
	run("chown", "-R", fmt.Sprintf("%d:%d", importerUID, importerGID), importerAttackerPackage)
	attackerImportEnv := withEnvironment(importerEnv, importSnapshotEnv, importerAttackerPackage)
	rejectedImportOutput, err := runAs(importerUser, withEnvironment(attackerImportEnv, "PQ40E_REJECT_UNAUTHORIZED_ANCHOR", "1"), "TestPQ40EControlledSnapshotImporterChild")
	require.NoError(t, err, rejectedImportOutput)
	require.NoFileExists(t, filepath.Join(peerRoot, "acceptance.json"))
	require.NoError(t, os.WriteFile(joinPath, anchor, 0o400))
	importOutput, err := runAs(importerUser, importerEnv, "TestPQ40EControlledSnapshotImporterChild")
	require.NoError(t, err, importOutput)
	require.NoFileExists(t, filepath.Join(peerRoot, "acceptance.json"))
	recoveryOutput, err := runAs(importerUser, withEnvironment(importerEnv, importRecoveryEnv, "1"), "TestPQ40EControlledSnapshotImporterChild")
	require.NoError(t, err, recoveryOutput)
	acceptanceBytes, err := os.ReadFile(filepath.Join(peerRoot, "acceptance.json"))
	require.NoError(t, err)
	var importResult struct {
		Imported                bool `json:"imported"`
		Recovered               bool `json:"recovered"`
		BaselineLedgerPreserved bool `json:"baseline_ledger_preserved"`
	}
	require.NoError(t, json.Unmarshal(acceptanceBytes, &importResult))
	require.True(t, importResult.Imported)
	require.True(t, importResult.Recovered)
	require.True(t, importResult.BaselineLedgerPreserved)

	exportEvidence, err = os.ReadFile(filepath.Join(export.Directory(), enrollment.SnapshotExportEvidenceFileName))
	require.NoError(t, err)
	signableBytes, err := os.ReadFile(filepath.Join(export.Directory(), kvledger.SnapshotSignableMetadataFileName))
	require.NoError(t, err)
	additionalBytes, err := os.ReadFile(filepath.Join(export.Directory(), kvledger.SnapshotAdditionalMetadataFileName))
	require.NoError(t, err)
	exporterPublicKeyHash := hashBytes(authorization.ExporterPublicKey)
	anchorHash := hashBytes(anchor)
	gitCommit, worktreeClean := currentGitState(t)
	acceptance := provisioningAcceptanceEvidence{
		SchemaVersion:            "fabric-pq/provisioning-acceptance/v1",
		GitCommit:                gitCommit,
		WorktreeClean:            worktreeClean,
		CIWorkflow:               os.Getenv("GITHUB_WORKFLOW"),
		CIJob:                    os.Getenv("GITHUB_JOB"),
		CIRunID:                  os.Getenv("GITHUB_RUN_ID"),
		CIRunAttempt:             os.Getenv("GITHUB_RUN_ATTEMPT"),
		ExporterBinarySHA256:     binaryHash,
		ImporterBinarySHA256:     binaryHash,
		AuthorizationIdentity:    verifiedAuthorization.Authorization().ApprovalIdentity,
		AuthorizationDigest:      hashBytes(authorizationBytes),
		ExporterOperationDigest:  hashBytes(persistedOperationBytes),
		ExporterIdentity:         authorization.ExporterIdentity,
		ExporterPublicKeySHA256:  exporterPublicKeyHash,
		SourceLedgerIdentity:     authorization.SourceLedgerIdentity,
		SourceLedgerPath:         authorization.SourceLedgerPath,
		ControlledInvocation:     append(operation.Launcher, operation.Invocation...),
		Channel:                  authorization.Channel,
		TrustedGenesisIdentity:   report.TrustedGenesisBlockIdentity,
		VerifiedHistoryIdentity:  report.SourceHistoryIdentity,
		ConfigurationSequence:    authorization.ConfigurationSequence,
		SnapshotBlockNumber:      authorization.SnapshotBlockNumber,
		SnapshotBlockHash:        authorization.SnapshotBlockHash,
		ConfigurationDigest:      authorization.ConfigurationDigest,
		SignableMetadataDigest:   hashBytes(signableBytes),
		AdditionalMetadataDigest: hashBytes(additionalBytes),
		ExporterEvidenceDigest:   hashBytes(exportEvidence),
		SnapshotInventoryDigest:  snapshotInventoryDigest(t, export.Directory()),
		PeerJoinAnchorDigest:     anchorHash,
		ImportResult:             "passed",
		RecoveryResult:           "passed",
		BaselineLedgerContinuity: "passed",
	}
	acceptanceBytesOut, err := json.Marshal(acceptance)
	require.NoError(t, err)
	acceptancePath := os.Getenv(acceptanceRecordEnv)
	if acceptancePath == "" {
		acceptancePath = filepath.Join(workspace, "pq40e3-acceptance.json")
	}
	require.NoError(t, os.WriteFile(acceptancePath, acceptanceBytesOut, 0o600))
	t.Logf("PQ4.0E.3 non-secret evidence manifest: %s", acceptancePath)
}

func TestPQ40EControlledSnapshotExporterChild(t *testing.T) {
	if os.Getenv(exporterChildEnv) != "1" {
		t.Skip("subprocess-only exporter test")
	}
	authorityKey, err := os.ReadFile(os.Getenv(authorityPublicKeyEnv))
	require.NoError(t, err)
	authorityPublicKey, err := mldsa.NewPublicKey(mldsa.MLDSA65(), authorityKey)
	require.NoError(t, err)
	authorizationBytes, err := os.ReadFile(os.Getenv(authorizationFileEnv))
	require.NoError(t, err)
	verifiedAuthorization, err := provisioning.VerifyExporterAuthorization(
		authorizationBytes, os.Getenv(authorityIdentityEnv), authorityPublicKey,
	)
	require.NoError(t, err)
	authorization := verifiedAuthorization.Authorization()
	if override := os.Getenv(exporterOverrideEnv); override != "" && override != authorization.SourceLedgerPath {
		t.Fatalf("unauthorized source-ledger override: %s", override)
	}
	require.NoError(t, verifiedAuthorization.VerifyAuthorizedSourcePath())
	privateKeyBytes, err := os.ReadFile(os.Getenv(exporterPrivateKeyEnv))
	require.NoError(t, err)
	exporterSigner, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), privateKeyBytes)
	require.NoError(t, err)
	require.Equal(t, authorization.ExporterPublicKey, exporterSigner.Public().(*mldsa.PublicKey).Bytes())

	manager, err := constructLedgerMgrWithTestDefaults(authorization.SourceLedgerPath)
	require.NoError(t, err)
	defer manager.Close()
	source, err := manager.OpenLedger(authorization.Channel)
	require.NoError(t, err)
	block, err := source.GetBlockByNumber(authorization.SnapshotBlockNumber)
	require.NoError(t, err)
	require.Equal(t, authorization.SnapshotBlockHash, hex.EncodeToString(protoutil.BlockHeaderHash(block.GetHeader())))
	info, err := source.GetBlockchainInfo()
	require.NoError(t, err)
	require.GreaterOrEqual(t, info.GetHeight(), authorization.SnapshotBlockNumber+1)
	require.NoError(t, source.SubmitSnapshotRequest(authorization.SnapshotBlockNumber))
	snapshotDir := kvledger.SnapshotDirForLedgerBlockNum(
		filepath.Join(authorization.SourceLedgerPath, "snapshots"),
		authorization.Channel,
		authorization.SnapshotBlockNumber,
	)
	require.Eventually(t, func() bool {
		pending, err := source.PendingSnapshotRequests()
		return err == nil && len(pending) == 0
	}, 30*time.Second, 100*time.Millisecond)
	claims := provisioning.SnapshotExportClaims{
		Network: authorization.Network, Channel: authorization.Channel,
		ExporterIdentity:      authorization.ExporterIdentity,
		SourceLedgerIdentity:  authorization.SourceLedgerIdentity,
		GenesisIdentity:       authorization.TrustedGenesis,
		SnapshotBlockNumber:   authorization.SnapshotBlockNumber,
		SnapshotBlockHash:     authorization.SnapshotBlockHash,
		ConfigurationSequence: authorization.ConfigurationSequence,
		ConfigurationDigest:   authorization.ConfigurationDigest,
		SourceHistoryIdentity: authorization.SourceHistoryIdentity,
		TransportProfile:      authorization.TransportProfile,
	}
	exportEvidence, err := provisioning.SignSnapshotExportEvidence(snapshotDir, claims, exporterSigner)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(snapshotDir, enrollment.SnapshotExportEvidenceFileName), exportEvidence, 0o400))
}

func TestPQ40EControlledSnapshotImporterChild(t *testing.T) {
	if os.Getenv(importerChildEnv) != "1" {
		t.Skip("subprocess-only importer test")
	}
	peerRoot := os.Getenv(importRootEnv)
	authorityBytes, err := os.ReadFile(os.Getenv(authorityPublicKeyEnv))
	require.NoError(t, err)
	authorityKey, err := mldsa.NewPublicKey(mldsa.MLDSA65(), authorityBytes)
	require.NoError(t, err)
	manifestBytes, err := os.ReadFile(os.Getenv(manifestFileEnv))
	require.NoError(t, err)
	historyBytes, err := os.ReadFile(os.Getenv(historyFileEnv))
	require.NoError(t, err)
	manifest, err := enrollment.Verify(manifestBytes, historyBytes, authorityKey)
	require.NoError(t, err)
	require.Equal(t, filepath.Join(peerRoot, "ledgersData"), manifest.LedgerDir)
	require.Equal(t, filepath.Join(peerRoot, "state"), manifest.StateDir)
	startPeer := func() (*Peer, func()) {
		p, closeLedger := newTestPeer(t, peerRoot)
		registry, err := enrollment.OpenProtectedRegistry(manifest)
		require.NoError(t, err)
		p.ProtectedRegistry = registry
		p.Initialize(nil, nil, nil, nil, nil, nil, 1)
		closePeer := sync.OnceFunc(func() {
			p.GossipService.Stop()
			p.StoreProvider.Close()
			closeLedger()
		})
		return p, closePeer
	}
	if os.Getenv("PQ40E_REJECT_UNAUTHORIZED_ANCHOR") == "1" {
		p, closePeer := startPeer()
		defer closePeer()
		err := p.CreateChannelFromSnapshot(os.Getenv(importSnapshotEnv), nil, nil, nil)
		require.ErrorContains(t, err, "controlled execution conflicts with snapshot export evidence")
		require.Nil(t, p.Channel(testfixture.ChannelID))
		ids, err := p.LedgerMgr.GetLedgerIDs()
		require.NoError(t, err)
		require.Empty(t, ids)
		return
	}
	run := func(snapshotPath string, doImport bool) {
		p, closePeer := startPeer()
		defer closePeer()
		if doImport {
			_, genesisB := testutil.NewBlockGenerator(t, "baseline-channel", false)
			_, err := p.LedgerMgr.CreateLedger("baseline-channel", genesisB)
			require.NoError(t, err)
			require.NoError(t, p.CreateChannelFromSnapshot(snapshotPath, nil, nil, nil))
		}
		require.Eventually(t, func() bool {
			channel := p.Channel(testfixture.ChannelID)
			return channel != nil && channel.activation.Ready() && !p.JoinBySnapshotStatus().GetInProgress()
		}, 15*time.Second, 50*time.Millisecond)
		ids, err := p.LedgerMgr.GetLedgerIDs()
		require.NoError(t, err)
		require.Contains(t, ids, testfixture.ChannelID)
		require.Contains(t, ids, "baseline-channel")
	}
	if os.Getenv(importRecoveryEnv) != "1" {
		run(os.Getenv(importSnapshotEnv), true)
		return
	}
	run("", false)
	result, err := json.Marshal(struct {
		Imported                bool `json:"imported"`
		Recovered               bool `json:"recovered"`
		BaselineLedgerPreserved bool `json:"baseline_ledger_preserved"`
	}{Imported: true, Recovered: true, BaselineLedgerPreserved: true})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(os.Getenv(acceptanceRecordEnv), result, 0o600))
}

func signProvisioningTestAnchor(t *testing.T, signer *mldsa.PrivateKey, anchor any) ([]byte, error) {
	t.Helper()
	return signProvisioningTestDocument(signer, enrollment.PeerSnapshotAnchorDomain, anchor)
}

func signProvisioningTestDocument(signer *mldsa.PrivateKey, domain string, document any) ([]byte, error) {
	payload, err := json.Marshal(document)
	if err != nil {
		return nil, err
	}
	signature, err := signer.Sign(rand.Reader, append([]byte(domain), payload...), nil)
	if err != nil {
		return nil, err
	}
	return json.Marshal(enrollment.Envelope{Payload: payload, Signature: signature})
}

func createControlledProvisioningLedger(t *testing.T, dataDir, channel string, blocks ...*cb.Block) {
	t.Helper()
	manager, err := constructLedgerMgrWithTestDefaults(dataDir)
	require.NoError(t, err)
	defer manager.Close()
	if len(blocks) == 0 {
		t.Fatal("a native ledger requires a genesis block")
	}
	source, err := manager.CreateLedger(channel, blocks[0])
	require.NoError(t, err)
	for _, block := range blocks[1:] {
		require.NoError(t, source.CommitLegacy(&ledger.BlockAndPvtData{Block: block}, &ledger.CommitOptions{}))
	}
}

func copyTestBinary(t *testing.T, destination string) (string, error) {
	t.Helper()
	source, err := os.Executable()
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(source)
	if err != nil {
		return "", err
	}
	target := filepath.Join(destination, "pq40e3-peer.test")
	if err := os.WriteFile(target, data, 0o755); err != nil {
		return "", err
	}
	return target, nil
}

func withEnvironment(environment map[string]string, name, value string) map[string]string {
	clone := maps.Clone(environment)
	clone[name] = value
	return clone
}

func hashBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func hashFile(t *testing.T, path string) string {
	t.Helper()
	value, err := os.ReadFile(path)
	require.NoError(t, err)
	return hashBytes(value)
}

func currentGitState(t *testing.T) (string, bool) {
	t.Helper()
	output, err := exec.Command("git", "rev-parse", "HEAD").Output()
	require.NoError(t, err)
	status, err := exec.Command("git", "status", "--porcelain").Output()
	require.NoError(t, err)
	return strings.TrimSpace(string(output)), strings.TrimSpace(string(status)) == ""
}

func snapshotInventoryDigest(t *testing.T, directory string) string {
	t.Helper()
	signable, err := os.ReadFile(filepath.Join(directory, kvledger.SnapshotSignableMetadataFileName))
	require.NoError(t, err)
	var metadata kvledger.SnapshotSignableMetadata
	require.NoError(t, json.Unmarshal(signable, &metadata))
	var names []string
	for name := range metadata.FilesAndHashes {
		names = append(names, name)
	}
	sort.Strings(names)
	inventory := make([][2]string, 0, len(names))
	for _, name := range names {
		inventory = append(inventory, [2]string{name, metadata.FilesAndHashes[name]})
	}
	encoded, err := json.Marshal(inventory)
	require.NoError(t, err)
	return hashBytes(encoded)
}
