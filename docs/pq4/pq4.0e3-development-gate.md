# PQ4.0E.3 development gate proposal

**Decision: INCOMPLETE — ADDITIONAL EVIDENCE REQUIRED**

PQ4.0E.3 implements signed pre-export authorization, source-ledger path
controls, controlled native Fabric snapshot generation, independent
verification, v2 approval, and protected import/recovery under separate Linux
identities. The local controlled acceptance test passes. This report does not
propose PASS because the final-head hosted Verify Build/PQ3 matrix, retained
final-head evidence, and independent review have not yet been completed.

## Trust boundary and assumptions

See the [PQ4.0E.3 provisioning decision](pq4.0e3-provisioning.md). The
provisioning authority authenticates its exporter authorization before export
and records the launch result. The exporter process runs as a separate user
with access to only the approved ledger path. The importing peer runs as a
third user and accepts only the existing v2 signed peer snapshot anchor and
authenticated evidence. The test trusts the disposable VM kernel and
privileged test driver; it does not claim resistance to privileged-host
compromise, total host-state rollback, or deliberate false signing by a
trusted exporter.

## Security-property matrix

| Required invariant | Implementation and named test | Evidence class | Exact tested revision and workflow/job | Result | Remaining assumption or limitation | Gate decision |
| --- | --- | --- | --- | --- | --- | --- |
| Protected enrollment and startup authenticate the node before serving | `cmd/pq-launcher`; `TestPQ40EDisposableVMService`; managed peer/orderer startup and restart tests | Native processes and disposable systemd VM | Historical H2 `a5295383f3faf8bbbad06388f5cc0aa029970a4f` / M2 `9d4aee18e968f961d79a0a39daebd81c57c53116`; Verify Build #45810211331 | Historical focused job passed | Production host provisioning and complete privileged-host rollback are out of scope | Pending final-head regression |
| Service-manager boundary prevents exporter/importer identities from replacing trusted launch/config | Root-controlled systemd unit and installer; `TestPQ40EDisposableVMService` | Disposable VM | H2/M2; Verify Build #45810211331 PQ4.0E job | Historical VM test passed | VM kernel and privileged provisioner are trusted | Pending final-head regression |
| Fabric history is verified from independently trusted genesis before approval | `provisioning.VerifyJoinHistory`; provenance tests; `TestPQ40EManagedOrdererNonGenesisPromotion`; snapshot import test | Native Fabric ledger and orderer/peer tests | H2/M2; Verify Build #45810211331 PQ4.0E.1 job | Historical focused tests passed | History verification does not reconstruct or attest arbitrary snapshot world state | Pending final-head regression |
| Exporter identity/key and source-ledger path are authorized before package creation | `SignExporterAuthorization`, `VerifyExporterAuthorization`, `SnapshotExporterTrust(VerifiedJoinHistory)`; `TestPQ40EControlledSnapshotProvisioning` | Race-enabled disposable Linux process/filesystem test; distinct authority, exporter and importer identities | Local Go 1.27.4 container run on worktree based on `4dafb5f7e3aca0c7fd70fe9613e1b6250108111b`; final-head `pq40e3-provisioning-gate` job pending | Local test passed; hosted exact-head evidence pending | The authorization path is an OS-controlled association, not cryptographic source-ledger attestation | INCOMPLETE until final-head CI and independent review |
| Only the authorized native ledger/channel/boundary is exported | Controlled exporter verifies the signed path, opens `LedgerMgr` on that root, checks the authorized block hash, then requests native snapshot generation; Ledger A/B case in `TestPQ40EControlledSnapshotProvisioning` | Native Fabric ledger opened by a separate exporter process; OS read-denial check | Same local worktree test; final-head `pq40e3-provisioning-gate` job pending | Ledger A succeeds; Ledger B path is inaccessible and override is rejected before approval | The exporter and host kernel remain trusted | INCOMPLETE until final-head CI and independent review |
| Self-authorized exporter/key cannot create approval | Attacker-key authorization, self-signed package, and attacker-signed anchor replacement cases in `TestPQ40EControlledSnapshotProvisioning`; existing unapproved exporter tests in `TestPQ40ESignedNonGenesisSnapshotJoinAndRecovery` | Native exporter evidence, independent verifier, and separate importer process | New local worktree test; historical PQ4.0E.2 tests H2/M2, Verify Build #45810211331 | Local attacker cases rejected before import; historical focused job passed | Does not detect a malicious exporter holding the independently authorized key | Pending final-head CI |
| Snapshot evidence binds exact metadata, full inventory and staged bytes | `VerifySnapshotExport`, `SignVerifiedPeerSnapshotAnchor`; `TestPQ40ESignedNonGenesisSnapshotJoinAndRecovery`; post-stage replacement in `TestPQ40EControlledSnapshotProvisioning` | Native snapshot and protected staging tests | Historical H2/M2; new local worktree test; final-head job pending | Historical suite and local boundary test passed | Hash/signature checks cannot prove arbitrary world-state correctness | Pending final-head CI |
| Operator approval is issued only from verified opaque export result | `VerifiedSnapshotExport`; `SignVerifiedPeerSnapshotAnchor`; provenance enrollment tests | Native API and peer tests | H2/M2, Verify Build #45810211331; new local worktree test | Existing API tests and local approval path passed | Operator private key remains in trusted provisioning scope and is never placed in the export package | Pending final-head CI |
| Protected import/recovery stays closed until authenticated evidence and readiness | `stageProtectedSnapshot`, `recoverProtectedSnapshot`; `TestPQ40EControlledSnapshotImporterChild`; restart evidence tests in `TestPQ40ESignedNonGenesisSnapshotJoinAndRecovery` | Separate importer process, native peer lifecycle, durable recovery | Historical H2/M2; new local worktree test; final-head job pending | Local protected import and restart recovery passed | Test exercises native peer code in the controlled test binary; kernel/privileged-host trust remains | Pending final-head CI |
| Native peer/orderer admission and Raft readiness remain protected | PQ4.0D Raft/quarantine tests; PQ4.0E managed peer/orderer admission and promotion tests | Native peer/orderer tests | H2/M2, Verify Build #45810211331 PQ4.0D and PQ4.0E jobs | Historical focused jobs passed | Not a distributed network certification | Pending final-head regression |
| Activation and crash/restart recovery preserve checkpoint invariants | PQ4.0C activation tests and recovery matrix; affected PQ4.0E tests | Native peer/orderer and ledger tests | H2/M2, Verify Build #45810211331 PQ4.0C job | Historical focused job passed | Power-loss and privileged rollback of all host state are not demonstrated | Pending final-head regression |
| Strict transport remains enforced at existing managed endpoints | PQ4.0E strict listener, administration, gossip, Gateway, Deliver and managed launcher tests | Component/native process and disposable-VM tests | H2/M2, Verify Build #45810211331 PQ4.0E job | Historical focused job passed | Does not establish PQ4.0B network-wide capability or unsupported-binary enforcement | Pending final-head regression |
| Mixed-channel and baseline Fabric behavior remain intact | `core/peer/pq40e_mixed_channel_test.go`; full peer/unit/integration tests; baseline ledger continuity in controlled importer test | Native peer and repository regression suites | Historical H2/M2; new local worktree test; final-head full matrix pending | Historical full matrix passed; local baseline ledger preserved | Production topology and distributed CCAAS are excluded | Pending final-head regression |
| PQ3 compatibility remains accepted | PQ3 isolated acceptance workflow, both profile runs and evidence-package verification | Isolated hosted acceptance | H2/M2, PQ3 run #45810211209 | Historical run passed | Must be rerun against the final PR head | INCOMPLETE until final-head run |
| Full matrix and independent final review support the gate decision | Verify Build, all focused PQ4 jobs, Basic Checks, all unit/integration groups, PQ3, binary hashes and independent review | Final-head hosted CI and independent review | New final-head workflow runs and reviewer sign-off not yet available | Not yet run/reviewed | Codex must not self-certify its own security review; do not merge automatically | **INCOMPLETE** |

## Controlled falsification results

`TestPQ40EControlledSnapshotProvisioning` builds two genuine native Fabric
ledger roots and performs the following cases:

1. **Authorized source:** the root-controlled authority signs authorization
   for Ledger A, exporter A and its public-key pin. The exporter user opens
   Ledger A, checks the exact authorized block, generates and signs a native
   snapshot, and the provisioner verifies history/evidence before v2 approval.
   A separate importer user imports and restarts the protected peer. The
   channel reaches readiness and the baseline ledger remains present.
2. **Wrong actual source:** the exporter is given Ledger B as a source
   override while authorization names A. The executor rejects the override;
   the exporter UID also cannot read Ledger B. No join anchor is issued by
   the failed path.
3. **Self-authorized replacement:** an attacker-generated key signs a new
   authorization and a self-consistent snapshot evidence package. The
   provisioner rejects both because the authority identity/key and exporter
   pin were fixed independently before export. A separately signed v2 anchor
   that attempts to replace the approved exporter key and identity is rejected
   by the importing peer before channel creation; no partial ledger is left.

The test also modifies the original evidence file after private staging; the
operator signs and the importer consumes only the verified staged bytes. This
demonstrates the intended source-selection and staging controls, not protection
from compromise of the trusted exporter, provisioning authority, or VM kernel.

## Local validation

The following command passed in a disposable `golang:1.27.4` Linux/amd64
container running as root, with vendored dependencies and race detection:

```text
GOFIPS140=off GOFLAGS=-buildvcs=false PQ40E_PROVISIONING_VM=1 go test -mod=vendor -race -count=1 -v -run '^TestPQ40EControlledSnapshotProvisioning$' ./core/peer
```

The following target also passed in the same container, including the
provisioning package tests, controlled provisioning and existing signed
snapshot join/recovery tests, and `go vet`:

```text
GOFIPS140=off GOFLAGS=-buildvcs=false PQ40E_PROVISIONING_VM=1 make pq-provisioning-acceptance
```

The existing native snapshot-import regression passed:

```text
GOFIPS140=off GOFLAGS=-buildvcs=false go test -mod=vendor -race -count=1 -run '^TestCreateChannelBySnapshot$' ./core/peer
```

These commands validate the current working tree, not an immutable commit.
The new final-head hosted workflow job must pass after commit. The complete
Verify Build matrix and PQ3 isolated acceptance must also pass on that exact
head, with transient failures and retries reported separately and skipped
tests never counted as passes.

## Decision

**INCOMPLETE — ADDITIONAL EVIDENCE REQUIRED.** The controlled authorization and
source-ledger demonstration is implemented and passes locally, but final-head
hosted CI and an independent architecture/security review remain mandatory.
If the hosted evidence passes, request independent review; do not treat this
proposal as an accepted gate until that review explicitly accepts the final
commit and evidence. Keep production deployment, PQ4.0B.1, v1 migration,
distributed CCAAS certification, and PQ4.1–PQ4.5 out of scope.
