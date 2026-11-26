//go:build linux

/*
SPDX-License-Identifier: Apache-2.0
*/

package peer

import (
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	pb "github.com/hyperledger/fabric-protos-go-apiv2/peer"
	"github.com/hyperledger/fabric/core/ledger"
	"github.com/hyperledger/fabric/core/ledger/kvledger"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation/testfixture"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/enrollment"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/provisioning"
	"github.com/hyperledger/fabric/protoutil"
	"github.com/stretchr/testify/require"
)

func TestPQ40ESignedNonGenesisSnapshotJoinAndRecovery(t *testing.T) {
	fixture := testfixture.New(t)
	genesis := fixture.RaftGenesis(t)
	update := fixture.Update(t, testfixture.Config(t, genesis))
	block := fixture.SignedBlock(t, genesis, fixture.Envelope(t, update), 1)
	block.Metadata.Metadata[cb.BlockMetadataIndex_TRANSACTIONS_FILTER] = []byte{byte(pb.TxValidationCode_VALID)}
	exportRoot := t.TempDir()
	exporter, err := constructLedgerMgrWithTestDefaults(exportRoot)
	require.NoError(t, err)
	closeExporter := sync.OnceFunc(exporter.Close)
	t.Cleanup(closeExporter)
	source, err := exporter.CreateLedger(testfixture.ChannelID, genesis)
	require.NoError(t, err)
	require.NoError(t, source.CommitLegacy(&ledger.BlockAndPvtData{Block: block}, &ledger.CommitOptions{}))
	require.NoError(t, source.SubmitSnapshotRequest(1))
	snapshot := kvledger.SnapshotDirForLedgerBlockNum(filepath.Join(exportRoot, "snapshots"), testfixture.ChannelID, 1)
	require.Eventually(t, func() bool {
		pending, err := source.PendingSnapshotRequests()
		return err == nil && len(pending) == 0
	}, 10*time.Second, 20*time.Millisecond)
	signable, err := os.ReadFile(filepath.Join(snapshot, kvledger.SnapshotSignableMetadataFileName))
	require.NoError(t, err)
	additional, err := os.ReadFile(filepath.Join(snapshot, kvledger.SnapshotAdditionalMetadataFileName))
	require.NoError(t, err)
	closeExporter()

	root, state := t.TempDir(), t.TempDir()
	store, err := activation.OpenStore(state, nil)
	require.NoError(t, err)
	fixture.Provision(t, store, update.GetConfig())
	key := fixture.Channel(store, activation.Ledger{}).Signer.Bytes()
	keyFile := filepath.Join(state, "policy-key")
	require.NoError(t, os.WriteFile(keyFile, key, 0o600))
	channelDigest := sha256.Sum256([]byte(testfixture.ChannelID))
	genesisName := filepath.Join(state, fmt.Sprintf("genesis-%x", channelDigest))
	genesisHash, err := json.Marshal(hex.EncodeToString(protoutil.BlockHeaderHash(genesis.GetHeader())))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(genesisName, genesisHash, 0o600))
	require.NoError(t, os.WriteFile(genesisName+".block", protoutil.MarshalOrPanic(genesis), 0o600))
	joinName := filepath.Join(state, fmt.Sprintf("join-peer-%x", channelDigest))
	require.NoError(t, os.WriteFile(joinName+".block", protoutil.MarshalOrPanic(block), 0o600))
	manifest := &enrollment.Manifest{
		Mode: enrollment.Protected, Network: testfixture.Network, Node: testfixture.Node,
		Profile: pqtransport.ProfileV1, PolicySigner: keyFile, PolicySignerDigest: fmt.Sprintf("%x", sha256.Sum256(key)),
		StateDir: state, LedgerDir: filepath.Join(root, "ledgersData"), Generation: 1,
		Executable: filepath.Join(root, "peer"), SnapshotAuthority: "test-provisioner",
	}
	authority, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	manifestPayload, err := json.Marshal(manifest)
	require.NoError(t, err)
	manifestBytes, err := signProvisioningTestDocument(authority, "fabric-pq/enrollment/v1\x00", manifest)
	require.NoError(t, err)
	historyBytes, err := signProvisioningTestDocument(authority, "fabric-pq/enrollment-history/v1\x00", enrollment.History{
		Network: manifest.Network, Node: manifest.Node, Generation: manifest.Generation,
		ProtectedEver: true, ManifestDigest: hashBytes(manifestPayload),
	})
	require.NoError(t, err)
	authorityKey, err := mldsa.NewPublicKey(mldsa.MLDSA65(), authority.Public().(*mldsa.PublicKey).Bytes())
	require.NoError(t, err)
	manifest, err = enrollment.Verify(manifestBytes, historyBytes, authorityKey)
	require.NoError(t, err)
	replacementAuthority, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	*authorityKey = *replacementAuthority.Public().(*mldsa.PublicKey)
	modifiedManifest := *manifest
	modifiedManifest.SnapshotAuthority = "attacker"
	_, err = enrollment.OpenProtectedRegistry(&modifiedManifest)
	require.ErrorContains(t, err, "verified enrollment manifest was modified")
	var unsignedManifest enrollment.Manifest
	require.NoError(t, json.Unmarshal(manifestPayload, &unsignedManifest))
	_, err = enrollment.OpenProtectedRegistry(&unsignedManifest)
	require.ErrorContains(t, err, "requires verified enrollment")
	unsignedManifest.SnapshotAuthority = ""
	unsignedRegistry, err := enrollment.OpenProtectedRegistry(&unsignedManifest)
	require.NoError(t, err)
	registry, err := enrollment.OpenProtectedRegistry(manifest)
	require.NoError(t, err)
	_, authorityBytes := registry.SnapshotProvisioningAuthority()
	require.Equal(t, authority.Public().(*mldsa.PublicKey).Bytes(), authorityBytes)
	authorityBytes[0] ^= 0xff
	_, authorityBytes = registry.SnapshotProvisioningAuthority()
	require.Equal(t, authority.Public().(*mldsa.PublicKey).Bytes(), authorityBytes)
	verified, err := provisioning.VerifyJoinHistory(
		registry, testfixture.ChannelID, []*cb.Block{genesis, block}, block.GetHeader().GetNumber(), fixture.Crypto,
	)
	require.NoError(t, err)
	exporterSeed := sha256.Sum256([]byte("PQ4.0E.2 approved source exporter"))
	exporterSigner, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), exporterSeed[:])
	require.NoError(t, err)
	historyReport := verified.Report()
	exportEvidence, err := provisioning.SignSnapshotExportEvidence(snapshot, provisioning.SnapshotExportClaims{
		Network: testfixture.Network, Channel: testfixture.ChannelID,
		ExporterIdentity: "approved-source-peer", SourceLedgerIdentity: "source-ledger-01",
		GenesisIdentity:     historyReport.TrustedGenesisBlockIdentity,
		SnapshotBlockNumber: historyReport.TargetBlockNumber, SnapshotBlockHash: historyReport.TargetBlockHash,
		ConfigurationSequence: historyReport.TargetConfigurationSequence,
		ConfigurationDigest:   historyReport.TargetConfigurationDigest,
		SourceHistoryIdentity: historyReport.SourceHistoryIdentity,
		TransportProfile:      pqtransport.ProfileV1,
	}, exporterSigner)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(snapshot, enrollment.SnapshotExportEvidenceFileName), exportEvidence, 0o600))
	exporterTrust, err := provisioning.NewSnapshotExporterTrust(
		"approved-source-peer", "source-ledger-01", exporterSigner.Public().(*mldsa.PublicKey),
	)
	require.NoError(t, err)
	claims := provisioning.SnapshotExportClaims{
		Network: testfixture.Network, Channel: testfixture.ChannelID,
		ExporterIdentity: "approved-source-peer", SourceLedgerIdentity: "source-ledger-01",
		GenesisIdentity:     historyReport.TrustedGenesisBlockIdentity,
		SnapshotBlockNumber: historyReport.TargetBlockNumber, SnapshotBlockHash: historyReport.TargetBlockHash,
		ConfigurationSequence: historyReport.TargetConfigurationSequence,
		ConfigurationDigest:   historyReport.TargetConfigurationDigest,
		SourceHistoryIdentity: historyReport.SourceHistoryIdentity,
		TransportProfile:      pqtransport.ProfileV1,
	}
	rejectSnapshot := func(label string, mutate func(string)) {
		t.Helper()
		candidate := filepath.Join(t.TempDir(), label)
		copySnapshotPackage(t, snapshot, candidate)
		mutate(candidate)
		_, err := provisioning.VerifySnapshotExport(verified, candidate, exporterTrust)
		require.Error(t, err, label)
	}
	rejectSnapshot("missing-evidence", func(candidate string) {
		require.NoError(t, os.Remove(filepath.Join(candidate, enrollment.SnapshotExportEvidenceFileName)))
	})
	rejectSnapshot("tampered-evidence", func(candidate string) {
		path := filepath.Join(candidate, enrollment.SnapshotExportEvidenceFileName)
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		data[len(data)-1] ^= 1
		require.NoError(t, os.WriteFile(path, data, 0o600))
	})
	rejectSnapshot("unexpected-entry", func(candidate string) {
		require.NoError(t, os.WriteFile(filepath.Join(candidate, "unexpected.data"), []byte("unexpected"), 0o600))
	})
	rejectSnapshot("missing-payload", func(candidate string) {
		var metadata kvledger.SnapshotSignableMetadata
		require.NoError(t, json.Unmarshal(signable, &metadata))
		for name := range metadata.FilesAndHashes {
			require.NoError(t, os.Remove(filepath.Join(candidate, name)))
			return
		}
		t.Fatal("native snapshot contains no payload files")
	})
	rejectSnapshot("modified-payload", func(candidate string) {
		var metadata kvledger.SnapshotSignableMetadata
		require.NoError(t, json.Unmarshal(signable, &metadata))
		var names []string
		for name := range metadata.FilesAndHashes {
			names = append(names, name)
		}
		sort.Strings(names)
		path := filepath.Join(candidate, names[0])
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(path, append(data, 0x42), 0o600))
	})
	selfConsistentSnapshot := filepath.Join(t.TempDir(), "self-consistent-substitution")
	copySnapshotPackage(t, snapshot, selfConsistentSnapshot)
	rewriteSnapshotPayloadAndMetadata(t, selfConsistentSnapshot)
	_, err = provisioning.VerifySnapshotExport(verified, selfConsistentSnapshot, exporterTrust)
	require.Error(t, err, "recomputed native hashes do not replace fresh trusted-exporter approval")
	rejectSnapshot("symlink-payload", func(candidate string) {
		var metadata kvledger.SnapshotSignableMetadata
		require.NoError(t, json.Unmarshal(signable, &metadata))
		var names []string
		for name := range metadata.FilesAndHashes {
			names = append(names, name)
		}
		sort.Strings(names)
		path := filepath.Join(candidate, names[0])
		require.NoError(t, os.Remove(path))
		target := filepath.Join(t.TempDir(), "target.data")
		require.NoError(t, os.WriteFile(target, []byte("target"), 0o600))
		require.NoError(t, os.Symlink(target, path))
	})
	rejectSnapshot("non-regular-payload", func(candidate string) {
		var metadata kvledger.SnapshotSignableMetadata
		require.NoError(t, json.Unmarshal(signable, &metadata))
		var names []string
		for name := range metadata.FilesAndHashes {
			names = append(names, name)
		}
		sort.Strings(names)
		path := filepath.Join(candidate, names[0])
		require.NoError(t, os.Remove(path))
		require.NoError(t, os.Mkdir(path, 0o700))
	})
	for name, replace := range map[string]func(*provisioning.SnapshotExportClaims){
		"wrong-network":          func(c *provisioning.SnapshotExportClaims) { c.Network = "other-network" },
		"self-declared-exporter": func(c *provisioning.SnapshotExportClaims) { c.ExporterIdentity = "self-declared" },
		"wrong-source-ledger":    func(c *provisioning.SnapshotExportClaims) { c.SourceLedgerIdentity = "other-ledger" },
		"wrong-genesis": func(c *provisioning.SnapshotExportClaims) {
			c.GenesisIdentity = fmt.Sprintf("%x", sha256.Sum256([]byte("other-genesis")))
		},
		"wrong-config-sequence": func(c *provisioning.SnapshotExportClaims) { c.ConfigurationSequence++ },
		"wrong-config-digest": func(c *provisioning.SnapshotExportClaims) {
			c.ConfigurationDigest = fmt.Sprintf("%x", sha256.Sum256([]byte("other-config")))
		},
		"wrong-history": func(c *provisioning.SnapshotExportClaims) {
			c.SourceHistoryIdentity = fmt.Sprintf("%x", sha256.Sum256([]byte("other-history")))
		},
	} {
		candidate := filepath.Join(t.TempDir(), name)
		copySnapshotPackage(t, snapshot, candidate)
		require.NoError(t, os.Remove(filepath.Join(candidate, enrollment.SnapshotExportEvidenceFileName)))
		badClaims := claims
		replace(&badClaims)
		badEvidence, err := provisioning.SignSnapshotExportEvidence(candidate, badClaims, exporterSigner)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(candidate, enrollment.SnapshotExportEvidenceFileName), badEvidence, 0o600))
		_, err = provisioning.VerifySnapshotExport(verified, candidate, exporterTrust)
		require.Error(t, err, name)
	}
	wrongChannel := claims
	wrongChannel.Channel = "other-channel"
	_, err = provisioning.SignSnapshotExportEvidence(snapshot, wrongChannel, exporterSigner)
	require.ErrorContains(t, err, "conflict with native snapshot metadata")
	wrongHeight := claims
	wrongHeight.SnapshotBlockNumber++
	_, err = provisioning.SignSnapshotExportEvidence(snapshot, wrongHeight, exporterSigner)
	require.ErrorContains(t, err, "conflict with native snapshot metadata")
	unapprovedSeed := sha256.Sum256([]byte("unapproved snapshot exporter"))
	unapprovedSigner, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), unapprovedSeed[:])
	require.NoError(t, err)
	unapprovedTrust, err := provisioning.NewSnapshotExporterTrust(
		"approved-source-peer", "source-ledger-01", unapprovedSigner.Public().(*mldsa.PublicKey),
	)
	require.NoError(t, err)
	_, err = provisioning.VerifySnapshotExport(verified, snapshot, unapprovedTrust)
	require.ErrorContains(t, err, "verify authenticated snapshot export evidence")
	export, err := provisioning.VerifySnapshotExport(verified, snapshot, exporterTrust)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, export.Close()) })
	authorizationBytes, err := provisioning.SignExporterAuthorization(provisioning.ExporterAuthorization{
		AuthorityIdentity: "test-provisioner", Generation: 1, Network: testfixture.Network, Channel: testfixture.ChannelID,
		ExporterIdentity: "approved-source-peer", ExporterPublicKey: exporterSigner.Public().(*mldsa.PublicKey).Bytes(),
		SourceLedgerIdentity: "source-ledger-01", SourceLedgerPath: exportRoot,
		ExecutablePath: filepath.Join(exportRoot, "exporter"), ExecutableSHA256: hashBytes([]byte("exporter")),
		TrustedGenesis: historyReport.TrustedGenesisBlockIdentity, ConfigurationSequence: historyReport.TargetConfigurationSequence,
		ConfigurationDigest: historyReport.TargetConfigurationDigest, SnapshotBlockNumber: historyReport.TargetBlockNumber,
		SnapshotBlockHash: historyReport.TargetBlockHash, SourceHistoryIdentity: historyReport.SourceHistoryIdentity,
		TransportProfile: pqtransport.ProfileV1,
	}, authority)
	require.NoError(t, err)
	authorization, err := provisioning.VerifyExporterAuthorization(authorizationBytes, "test-provisioner", authority.Public().(*mldsa.PublicKey))
	require.NoError(t, err)
	authorized := authorization.Authorization()
	executionBytes, err := provisioning.SignExporterExecution(authorization, provisioning.ExporterExecution{
		AuthorizationDigest: hashBytes(authorizationBytes), ApprovalIdentity: authorized.ApprovalIdentity, Generation: authorized.Generation,
		SourceLedgerIdentity: authorized.SourceLedgerIdentity, SourceLedgerPath: authorized.SourceLedgerPath,
		Channel: authorized.Channel, SnapshotBlockNumber: authorized.SnapshotBlockNumber, SnapshotBlockHash: authorized.SnapshotBlockHash,
		ExecutablePath: authorized.ExecutablePath, ExecutableSHA256: authorized.ExecutableSHA256,
		ExportEvidenceDigest: hashBytes(exportEvidence), Launcher: []string{"trusted-launcher"},
		Invocation: []string{authorized.ExecutablePath}, Result: "success",
	}, authority)
	require.NoError(t, err)
	execution, err := provisioning.VerifyExporterExecution(authorization, executionBytes)
	require.NoError(t, err)
	seed := sha256.Sum256([]byte("PQ4.0C activation fixture operator"))
	signer, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), seed[:])
	require.NoError(t, err)
	operatorManifest, err := signProvisioningTestDocument(signer, "fabric-pq/enrollment/v1\x00", manifest)
	require.NoError(t, err)
	operatorHistory, err := signProvisioningTestDocument(signer, "fabric-pq/enrollment-history/v1\x00", enrollment.History{
		Network: manifest.Network, Node: manifest.Node, Generation: manifest.Generation,
		ProtectedEver: true, ManifestDigest: hashBytes(manifestPayload),
	})
	require.NoError(t, err)
	selfEnrolled, err := enrollment.Verify(operatorManifest, operatorHistory, signer.Public().(*mldsa.PublicKey))
	require.NoError(t, err)
	_, err = enrollment.OpenProtectedRegistry(selfEnrolled)
	require.ErrorContains(t, err, "must be independent of the policy signer")
	_, err = provisioning.SignVerifiedPeerSnapshotAnchor(verified, export, nil, execution, signer)
	require.Error(t, err)
	_, err = provisioning.SignVerifiedPeerSnapshotAnchor(verified, export, authorization, nil, signer)
	require.Error(t, err)
	policyExporter := authorized
	policyExporter.ExporterPublicKey = signer.Public().(*mldsa.PublicKey).Bytes()
	policyExporterBytes, err := provisioning.SignExporterAuthorization(policyExporter, authority)
	require.NoError(t, err)
	policyExporterAuth, err := provisioning.VerifyExporterAuthorization(policyExporterBytes, "test-provisioner", authority.Public().(*mldsa.PublicKey))
	require.NoError(t, err)
	_, err = policyExporterAuth.SnapshotExporterTrust(verified)
	require.ErrorContains(t, err, "independent of the policy signer")
	wrongOperatorSeed := sha256.Sum256([]byte("wrong operator signer"))
	wrongOperator, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), wrongOperatorSeed[:])
	require.NoError(t, err)
	_, err = provisioning.SignVerifiedPeerSnapshotAnchor(verified, export, authorization, execution, wrongOperator)
	require.ErrorContains(t, err, "does not match the authenticated")
	var stagedMetadata kvledger.SnapshotSignableMetadata
	require.NoError(t, json.Unmarshal(signable, &stagedMetadata))
	firstPayload := ""
	for name := range stagedMetadata.FilesAndHashes {
		firstPayload = name
		break
	}
	require.NotEmpty(t, firstPayload)
	require.NoError(t, os.Chmod(export.Directory(), 0o700))
	require.NoError(t, os.Chmod(filepath.Join(export.Directory(), firstPayload), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(export.Directory(), firstPayload), []byte("changed after staging"), 0o600))
	_, err = provisioning.SignVerifiedPeerSnapshotAnchor(verified, export, authorization, execution, signer)
	require.ErrorContains(t, err, "conflicts with authenticated digest")
	require.NoError(t, export.Close())
	export, err = provisioning.VerifySnapshotExport(verified, snapshot, exporterTrust)
	require.NoError(t, err)
	signed, err := provisioning.SignVerifiedPeerSnapshotAnchor(verified, export, authorization, execution, signer)
	require.NoError(t, err)
	var signedEnvelope enrollment.Envelope
	require.NoError(t, json.Unmarshal(signed, &signedEnvelope))
	var signedAnchor enrollment.PeerSnapshotAnchor
	require.NoError(t, json.Unmarshal(signedEnvelope.Payload, &signedAnchor))
	fakeAuthorization := authorized
	fakeAuthorization.ExporterPublicKey = unapprovedSigner.Public().(*mldsa.PublicKey).Bytes()
	fakeAuthorizationBytes, err := provisioning.SignExporterAuthorization(fakeAuthorization, signer)
	require.NoError(t, err)
	policyExecution := provisioning.ExporterExecution{
		AuthorizationDigest: hashBytes(policyExporterBytes), ApprovalIdentity: policyExporter.ApprovalIdentity,
		Generation: policyExporter.Generation, SourceLedgerIdentity: policyExporter.SourceLedgerIdentity,
		SourceLedgerPath: policyExporter.SourceLedgerPath, Channel: policyExporter.Channel,
		SnapshotBlockNumber: policyExporter.SnapshotBlockNumber, SnapshotBlockHash: policyExporter.SnapshotBlockHash,
		ExecutablePath: policyExporter.ExecutablePath, ExecutableSHA256: policyExporter.ExecutableSHA256,
		ExportEvidenceDigest: hashBytes(exportEvidence), Launcher: []string{"trusted-launcher"},
		Invocation: []string{policyExporter.ExecutablePath}, Result: "success",
	}
	policyExecutionBytes, err := provisioning.SignExporterExecution(policyExporterAuth, policyExecution, authority)
	require.NoError(t, err)
	for name, mutate := range map[string]func(*enrollment.PeerSnapshotAnchor){
		"missing authorization": func(a *enrollment.PeerSnapshotAnchor) { a.ExporterAuthorization = nil },
		"missing execution":     func(a *enrollment.PeerSnapshotAnchor) { a.ExporterExecution = nil },
		"self-selected authority": func(a *enrollment.PeerSnapshotAnchor) {
			a.ExporterAuthorization = fakeAuthorizationBytes
		},
		"exporter is policy signer": func(a *enrollment.PeerSnapshotAnchor) {
			a.ExporterAuthorization = policyExporterBytes
			a.ExporterExecution = policyExecutionBytes
			a.ExporterPublicKey = policyExporter.ExporterPublicKey
		},
		"modified authorization": func(a *enrollment.PeerSnapshotAnchor) {
			a.ExporterAuthorization = append([]byte(nil), a.ExporterAuthorization...)
			a.ExporterAuthorization[len(a.ExporterAuthorization)-1] ^= 1
		},
		"modified execution": func(a *enrollment.PeerSnapshotAnchor) {
			a.ExporterExecution = append([]byte(nil), a.ExporterExecution...)
			a.ExporterExecution[len(a.ExporterExecution)-1] ^= 1
		},
		"unauthorized exporter": func(a *enrollment.PeerSnapshotAnchor) {
			a.ExporterPublicKey = unapprovedSigner.Public().(*mldsa.PublicKey).Bytes()
		},
		"unauthorized source": func(a *enrollment.PeerSnapshotAnchor) { a.SourceLedgerIdentity = "other-source" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := signedAnchor
			mutate(&candidate)
			forged := fixture.SignedJoinAnchor(t, enrollment.PeerSnapshotAnchorDomain, candidate)
			require.NoError(t, os.WriteFile(joinName, forged, 0o600))
			_, err := registry.VerifyPeerSnapshot(signable, additional, exportEvidence, fixture.Crypto)
			require.Error(t, err)
		})
	}
	require.NoError(t, os.WriteFile(joinName, signed, 0o600))
	_, err = unsignedRegistry.VerifyPeerSnapshot(signable, additional, exportEvidence, fixture.Crypto)
	require.ErrorContains(t, err, "independent provisioning authority")
	require.NoError(t, os.Remove(joinName))
	startPeer := func() (*Peer, func()) {
		p, closeLedger := newTestPeer(t, root)
		registry, err := enrollment.OpenProtectedRegistry(manifest)
		require.NoError(t, err)
		p.ProtectedRegistry = registry
		p.Initialize(nil, nil, nil, nil, nil, nil, 1)
		closePeer := sync.OnceFunc(func() {
			p.GossipService.Stop()
			p.StoreProvider.Close()
			closeLedger()
		})
		t.Cleanup(closePeer)
		return p, closePeer
	}
	p, closePeer := startPeer()
	require.ErrorContains(t, p.CreateChannelFromSnapshot(snapshot, nil, nil, nil), "read join-peer anchor")
	anchor := enrollment.PeerSnapshotAnchor{
		JoinAnchor:             fixture.JoinAnchor(t, genesis, block),
		FormatVersion:          enrollment.PeerSnapshotAnchorFormat,
		SignableMetadataHash:   fmt.Sprintf("%x", sha256.Sum256(signable)),
		AdditionalMetadataHash: fmt.Sprintf("%x", sha256.Sum256(additional)),
		ExportEvidenceHash:     fmt.Sprintf("%x", sha256.Sum256(exportEvidence)),
		ExporterIdentity:       "approved-source-peer",
		SourceLedgerIdentity:   "source-ledger-01",
		ExporterPublicKey:      exporterSigner.Public().(*mldsa.PublicKey).Bytes(),
		ExporterAuthorization:  authorizationBytes,
		ExporterExecution:      executionBytes,
	}
	downgrade := anchor
	downgrade.Profile = "baseline"
	require.NoError(t, os.WriteFile(joinName, fixture.SignedJoinAnchor(t, enrollment.PeerSnapshotAnchorDomain, downgrade), 0o600))
	require.ErrorContains(t, p.CreateChannelFromSnapshot(export.Directory(), nil, nil, nil), "conflicts with independently authorized exporter")
	legacyAnchor := fixture.SignedJoinAnchor(t, "fabric-pq/peer-snapshot/v1\x00", struct {
		enrollment.JoinAnchor
		SignableMetadataHash   string `json:"signable_metadata_hash"`
		AdditionalMetadataHash string `json:"additional_metadata_hash"`
	}{
		JoinAnchor:             anchor.JoinAnchor,
		SignableMetadataHash:   anchor.SignableMetadataHash,
		AdditionalMetadataHash: anchor.AdditionalMetadataHash,
	})
	require.NoError(t, os.WriteFile(joinName, legacyAnchor, 0o600))
	require.ErrorContains(t, p.CreateChannelFromSnapshot(export.Directory(), nil, nil, nil), "verify join-peer anchor")
	partial := anchor
	partial.ExportEvidenceHash = ""
	require.NoError(t, os.WriteFile(joinName, fixture.SignedJoinAnchor(t, enrollment.PeerSnapshotAnchorDomain, partial), 0o600))
	require.ErrorContains(t, p.CreateChannelFromSnapshot(export.Directory(), nil, nil, nil), "signed peer join anchor")
	require.NoError(t, os.WriteFile(joinName, signed, 0o600))
	tamperedSnapshot := filepath.Join(t.TempDir(), "tampered-snapshot")
	copySnapshotPackage(t, export.Directory(), tamperedSnapshot)
	metadataPath := filepath.Join(tamperedSnapshot, kvledger.SnapshotAdditionalMetadataFileName)
	require.NoError(t, os.Chmod(metadataPath, 0o600))
	require.NoError(t, os.WriteFile(metadataPath, append(append([]byte(nil), additional...), '\n'), 0o600))
	require.ErrorContains(t, p.CreateChannelFromSnapshot(tamperedSnapshot, nil, nil, nil), "signed peer join anchor")
	ids, err := p.LedgerMgr.GetLedgerIDs()
	require.NoError(t, err)
	require.Empty(t, ids)
	require.ErrorContains(t, p.CreateChannelFromSnapshot(selfConsistentSnapshot, nil, nil, nil), "signed peer join anchor")
	require.Nil(t, p.Channel(testfixture.ChannelID), "self-consistent substituted state must not admit the protected channel")
	require.NoError(t, p.CreateChannelFromSnapshot(export.Directory(), nil, nil, nil))
	require.Eventually(t, func() bool {
		channel := p.Channel(testfixture.ChannelID)
		return channel != nil && channel.activation.Ready() && !p.JoinBySnapshotStatus().GetInProgress()
	}, 10*time.Second, 20*time.Millisecond)
	require.EqualValues(t, 1, p.Channel(testfixture.ChannelID).Sequence())
	closePeer()

	require.NoError(t, os.WriteFile(joinName, legacyAnchor, 0o600))
	legacyRecovery, closeLegacyRecovery := startPeer()
	require.Nil(t, legacyRecovery.Channel(testfixture.ChannelID), "v1 approval must not recover a protected snapshot channel")
	closeLegacyRecovery()
	missingProof := signedAnchor
	missingProof.ExporterExecution = nil
	require.NoError(t, os.WriteFile(joinName, fixture.SignedJoinAnchor(t, enrollment.PeerSnapshotAnchorDomain, missingProof), 0o600))
	missingProofRecovery, closeMissingProofRecovery := startPeer()
	require.Nil(t, missingProofRecovery.Channel(testfixture.ChannelID), "missing execution proof must not recover a protected snapshot channel")
	closeMissingProofRecovery()
	require.NoError(t, os.WriteFile(joinName, signed, 0o600))

	require.NoError(t, os.Remove(joinName))
	closed, closeClosed := startPeer()
	require.Nil(t, closed.Channel(testfixture.ChannelID), "missing persisted provenance must keep the channel closed")
	closeClosed()
	require.NoError(t, os.WriteFile(joinName, signed, 0o600))
	exportEvidencePath := joinName + ".export"
	require.NoError(t, os.Remove(exportEvidencePath))
	missingEvidence, closeMissingEvidence := startPeer()
	require.Nil(t, missingEvidence.Channel(testfixture.ChannelID), "missing exporter evidence must keep the channel closed")
	closeMissingEvidence()
	require.NoError(t, os.WriteFile(exportEvidencePath, exportEvidence, 0o600))
	restored, _ := startPeer()
	require.NotNil(t, restored.Channel(testfixture.ChannelID))
	require.True(t, restored.Channel(testfixture.ChannelID).activation.Ready())
	require.EqualValues(t, 1, restored.Channel(testfixture.ChannelID).Sequence())
}

func copySnapshotPackage(t *testing.T, source, destination string) {
	t.Helper()
	require.NoError(t, os.Mkdir(destination, 0o700))
	entries, err := os.ReadDir(source)
	require.NoError(t, err)
	for _, entry := range entries {
		require.True(t, entry.Type().IsRegular())
		data, err := os.ReadFile(filepath.Join(source, entry.Name()))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(destination, entry.Name()), data, 0o600))
	}
}

func rewriteSnapshotPayloadAndMetadata(t *testing.T, directory string) {
	t.Helper()
	signablePath := filepath.Join(directory, kvledger.SnapshotSignableMetadataFileName)
	signable, err := os.ReadFile(signablePath)
	require.NoError(t, err)
	var metadata kvledger.SnapshotSignableMetadata
	require.NoError(t, json.Unmarshal(signable, &metadata))
	var names []string
	for name := range metadata.FilesAndHashes {
		names = append(names, name)
	}
	sort.Strings(names)
	payloadPath := filepath.Join(directory, names[0])
	payload, err := os.ReadFile(payloadPath)
	require.NoError(t, err)
	payload = append(payload, []byte("substituted world state")...)
	require.NoError(t, os.WriteFile(payloadPath, payload, 0o600))
	payloadHash := sha256.Sum256(payload)
	metadata.FilesAndHashes[names[0]] = hex.EncodeToString(payloadHash[:])
	signable, err = metadata.ToJSON()
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(signablePath, signable, 0o600))
	additionalPath := filepath.Join(directory, kvledger.SnapshotAdditionalMetadataFileName)
	additional, err := os.ReadFile(additionalPath)
	require.NoError(t, err)
	var additionalMetadata struct {
		SnapshotHash        string `json:"snapshot_hash"`
		LastBlockCommitHash string `json:"last_block_commit_hash"`
	}
	require.NoError(t, json.Unmarshal(additional, &additionalMetadata))
	signableHash := sha256.Sum256(signable)
	additionalMetadata.SnapshotHash = hex.EncodeToString(signableHash[:])
	additional, err = json.MarshalIndent(additionalMetadata, "", "    ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(additionalPath, additional, 0o600))
}
