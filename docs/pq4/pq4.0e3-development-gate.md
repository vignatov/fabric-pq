# PQ4.0E.3 development gate proposal

**Decision: INCOMPLETE — ADDITIONAL EVIDENCE REQUIRED**

PQ4.0E.3 implements signed pre-export authorization, source-ledger path
controls, controlled native Fabric snapshot generation, independent
verification, v2 approval, and protected import/recovery under separate Linux
identities. The current authorization enforcement changes require new
final-head validation and independent review before this report can propose
PASS. The earlier hosted results below cover the previous revision only.

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
| Exporter identity/key and source-ledger path are authorized before package creation | `SignExporterAuthorization`, `VerifyExporterAuthorization`, `SnapshotExporterTrust(VerifiedJoinHistory)`; `TestPQ40EControlledSnapshotProvisioning` | Race-enabled disposable Linux process/filesystem test; distinct authority, exporter and importer identities | Historical `2a277829503a362aeb0c151417f2a3023ec75ca7`: Verify Build #45868004896 and #45867995716; final-head job pending | Historical VM test passed; new enforcement needs final-head validation | The authorization path is an OS-controlled association, not cryptographic source-ledger attestation | INCOMPLETE until final-head CI and independent review |
| Only the authorized native ledger/channel/boundary is exported | Controlled exporter verifies the signed path, opens `LedgerMgr` on that root, checks the authorized block hash, then requests native snapshot generation; Ledger A/B case in `TestPQ40EControlledSnapshotProvisioning` | Native Fabric ledger opened by a separate exporter process; OS read-denial check | Historical `2a277829503a362aeb0c151417f2a3023ec75ca7`: Verify Build #45868004896 and #45867995716; final-head job pending | Historical test: Ledger A succeeds; Ledger B is inaccessible and override rejected | The exporter and host kernel remain trusted | INCOMPLETE until final-head CI and independent review |
| Self-authorized exporter/key cannot create an authorized approval | Attacker-key authorization and self-signed package, caller-selected trust, and operator-signed attacker anchor in `TestPQ40EControlledSnapshotProvisioning` | Native exporter evidence, independent verifier, and separate importer process | `be8e9bb08ece237259398e32051d23ff34bcdb41`: E.3 VM jobs in Verify Build #45881993359 and #45881985020 | VM jobs passed; final-head evidence linked below | Does not detect a malicious authorized exporter; independent launcher pins remain trusted | **INCOMPLETE** pending final-head validation and independent review |
| Snapshot evidence binds exact metadata, full inventory and staged bytes | `VerifySnapshotExport`, `SignVerifiedPeerSnapshotAnchor`; `TestPQ40ESignedNonGenesisSnapshotJoinAndRecovery`; post-stage replacement in `TestPQ40EControlledSnapshotProvisioning` | Native snapshot and protected staging tests | Historical H2/M2 and `2a277829503a362aeb0c151417f2a3023ec75ca7`; final-head job pending | Historical suite and boundary test passed | Hash/signature checks cannot prove arbitrary world-state correctness | Pending final-head CI |
| Operator approval requires verified export and mandatory independent pre-export authorization | `VerifiedSnapshotExport`; `SignVerifiedPeerSnapshotAnchor`; signed execution record; import/recovery verification | Native API and peer tests | `be8e9bb08ece237259398e32051d23ff34bcdb41`: E.3 VM jobs in Verify Build #45881993359 and #45881985020 | VM jobs passed; final-head evidence linked below | Independent enrollment authority and trusted execution observer are required | **INCOMPLETE** pending final-head validation and independent review |
| Protected import/recovery stays closed until authenticated evidence and readiness | `stageProtectedSnapshot`, `recoverProtectedSnapshot`; `TestPQ40EControlledSnapshotImporterChild`; restart evidence tests in `TestPQ40ESignedNonGenesisSnapshotJoinAndRecovery` | Separate importer process, native peer lifecycle, durable recovery | Historical H2/M2 and `2a277829503a362aeb0c151417f2a3023ec75ca7`; final-head job pending | Historical protected import and restart recovery passed | Test exercises native peer code in the controlled test binary; kernel/privileged-host trust remains | Pending final-head CI |
| Native peer/orderer admission and Raft readiness remain protected | PQ4.0D Raft/quarantine tests; PQ4.0E managed peer/orderer admission and promotion tests | Native peer/orderer tests | H2/M2, Verify Build #45810211331 PQ4.0D and PQ4.0E jobs | Historical focused jobs passed | Not a distributed network certification | Pending final-head regression |
| Activation and crash/restart recovery preserve checkpoint invariants | PQ4.0C activation tests and recovery matrix; affected PQ4.0E tests | Native peer/orderer and ledger tests | H2/M2, Verify Build #45810211331 PQ4.0C job | Historical focused job passed | Power-loss and privileged rollback of all host state are not demonstrated | Pending final-head regression |
| Strict transport remains enforced at existing managed endpoints | PQ4.0E strict listener, administration, gossip, Gateway, Deliver and managed launcher tests | Component/native process and disposable-VM tests | H2/M2, Verify Build #45810211331 PQ4.0E job | Historical focused job passed | Does not establish PQ4.0B network-wide capability or unsupported-binary enforcement | Pending final-head regression |
| Mixed-channel and baseline Fabric behavior remain intact | `core/peer/pq40e_mixed_channel_test.go`; full peer/unit/integration tests; baseline ledger continuity in controlled importer test | Native peer and repository regression suites | Historical H2/M2 and `2a277829503a362aeb0c151417f2a3023ec75ca7`; final-head full matrix pending | Historical full matrix passed and baseline ledger preserved | Production topology and distributed CCAAS are excluded | Pending final-head regression |
| PQ3 compatibility remains accepted | PQ3 isolated acceptance workflow, both profile runs and evidence-package verification | Isolated hosted acceptance | `be8e9bb08ece237259398e32051d23ff34bcdb41`: PQ3 #45881993331 and #45881984993 | Both runs passed | Must be rerun against the final PR head | INCOMPLETE until final-head run |
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
3. **Self-authorized replacement:** the valid operator key signs a new
   authorization for an attacker-generated exporter key, which signs a
   self-consistent snapshot evidence package. The
   provisioner rejects both because the authority identity/key and exporter
   pin were fixed independently before export. A separately signed v2 anchor
   that attempts to replace the approved exporter key and identity is rejected
   by the importing peer before channel creation; no partial ledger is left.
   The test also exercises a self-chosen pin in the verifier and rejects
   approval with the valid operator key when authorization is absent or does
   not match that exporter.

The authority-signed operation record records the parent's observed successful exit
and the expected invocation, not an independently measured ledger selection.
Missing, rejected, and inconsistent records fail the controlled procedure.
Signer key, manifest, history, genesis, and join anchor replacement attempts
are denied to the importer; the trusted parent selects the launch inputs.

The test also modifies the original evidence file after private staging; the
operator signs and the importer consumes only the verified staged bytes. This
demonstrates the intended source-selection and staging controls, not protection
from compromise of the trusted exporter, provisioning authority, or VM kernel.

## Current worktree validation

The following commands passed in a disposable `golang:1.27.4` Linux container
with the current changes on top of `2a277829503a362aeb0c151417f2a3023ec75ca7`.
The first includes race-enabled authorization, enrollment, controlled
separate-user provisioning and snapshot import/recovery tests, followed by
`go vet`. The second covers the existing baseline snapshot import:

```text
GOFIPS140=off GOFLAGS=-buildvcs=false PQ40E_PROVISIONING_VM=1 make pq-provisioning-acceptance
GOFIPS140=off GOFLAGS=-buildvcs=false PQ40E_PROVISIONING_VM=1 go test -mod=vendor -race -count=1 -run '^TestCreateChannelBySnapshot$' ./core/peer
```

These are worktree results, not final-head hosted evidence.

## Historical validation

At `be8e9bb08ece237259398e32051d23ff34bcdb41`, PR Verify Build
[#45881993359](https://github.com/vignatov/fabric-pq/actions/runs/45881993359)
and push Verify Build
[#45881985020](https://github.com/vignatov/fabric-pq/actions/runs/45881985020)
each passed all 19 jobs, including the E.3 job. The
the downloaded [artifact](https://github.com/vignatov/fabric-pq/actions/runs/45881985020/artifacts/15148755927)
reported that exact commit, a clean worktree, and successful import,
fresh-process recovery and baseline continuity. Its authorization,
execution-record, exporter-evidence and anchor digests were respectively
`c0c53fd1ce1338f76eeeb9985ededa87795ad502a4d5f670a397760ceecd5dc5`,
`1cdde5dcc6d08f275d42691dc8aaa4be92b49e540a4edd41fb84885cc6c4d9de`,
`774c937cd0c93ee32b4c58c2475b67ef37bd0a053a2faba006afe85c84db40c9` and
`c9135a8b68df62b78956dd2734b2dc130c1be41b50cff441e5a7a113a82acb86`.
Both PQ3 isolated-network runs
[#45881993331](https://github.com/vignatov/fabric-pq/actions/runs/45881993331)
and [#45881984993](https://github.com/vignatov/fabric-pq/actions/runs/45881984993)
passed their temporary and permanent profiles and evidence verification.
The [final-head evidence record](https://github.com/vignatov/fabric-pq/pull/15#issuecomment-7201333814)
tracks the precise final revision, CI and review outcomes after this report's
documentation update.

At `50363572f017122719f997e5ea313e144b1deb04`, the authorization-enforcement
changes passed the E.3 disposable-VM job in PR Verify Build
[#45879606704](https://github.com/vignatov/fabric-pq/actions/runs/45879606704)
and push Verify Build
[#45879597742](https://github.com/vignatov/fabric-pq/actions/runs/45879597742).
The downloaded push artifact
[`pq40e3-acceptance-45879597742-1`](https://github.com/vignatov/fabric-pq/actions/runs/45879597742/artifacts/15145393631)
reported the exact commit, a clean worktree, and passed import, recovery and
baseline continuity. That revision recreated the peer within one importer
process; the current test uses a second importer process for recovery.
It recorded authorization digest
`831afe12038798ad2a647365a9330c1bbd6fbcbc57f9ac49c2c668e878d53ca0`,
execution-record digest
`600bc2a02a9046d64b30cd143350d77b7ed208c49144ba532441481d7bbc3ff5`,
and anchor digest
`171782fdc4ee9c07c363a7b347bc1311126d143aab8c0cabe17ac9b77af997ef`.
Both Verify Build runs **failed** Basic Checks due to `gofumpt` formatting;
Unit and Integration Tests were skipped and are not counted as passes. The
formatter issue was fixed subsequently, so these runs are not final-head evidence.

At `2a277829503a362aeb0c151417f2a3023ec75ca7`, prior to the authorization
enforcement changes, PR Verify Build [#45868004896](https://github.com/vignatov/fabric-pq/actions/runs/45868004896)
and push Verify Build [#45867995716](https://github.com/vignatov/fabric-pq/actions/runs/45867995716)
passed all 19 jobs, including the hosted E.3 disposable-VM test. PR PQ3
[#45868004866](https://github.com/vignatov/fabric-pq/actions/runs/45868004866)
and push PQ3 [#45867995725](https://github.com/vignatov/fabric-pq/actions/runs/45867995725)
passed. The push run retained the non-secret `pq40e3-acceptance-45867995716-1`
artifact, reporting that exact commit, a clean worktree, and successful import,
recovery and baseline continuity. These runs do not validate subsequent changes.

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

These commands validated the earlier working tree, not the current changes or an immutable commit.
Hosted Verify Build run #45857490242 at `ffd05c94c02436e3e9e94a94b5f9bf7c43fc8f4c`
failed Basic Checks and the PQ4.0E.3 VM job; Unit and Integration Tests were
skipped. PQ3 run #45857490045 passed at that head. These results do not cover
subsequent fixes or substitute for final-head evidence.
The new final-head hosted workflow job must pass after commit. The complete
Verify Build matrix and PQ3 isolated acceptance must also pass on that exact
head, with transient failures and retries reported separately and skipped
tests never counted as passes.

## Decision

**INCOMPLETE — ADDITIONAL EVIDENCE REQUIRED.** The controlled executor and
source-ledger demonstration are test-harness-only. The authorization
enforcement changes require final-head hosted CI and a new independent
architecture/security review.
If the hosted evidence passes, request independent review; do not treat this
proposal as an accepted gate until that review explicitly accepts the final
commit and evidence. Keep production deployment, PQ4.0B.1, v1 migration,
distributed CCAAS certification, and PQ4.1–PQ4.5 out of scope.
