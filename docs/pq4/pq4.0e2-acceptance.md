# PQ4.0E development acceptance report

**Decision: INCOMPLETE — ADDITIONAL EVIDENCE REQUIRED**

PQ4.0E.2 now implements an authenticated snapshot-export path and has focused
native-ledger, protected-import and recovery coverage. This report does not
self-certify the complete PQ4.0E gate. The initial PR revision received
focused hosted and disposable-VM evidence and an independent review, but its
full Verify Build did not complete. The current PR head must pass the full
matrix and the trusted provisioning assumptions still require evidence.

## Provenance and tested head

- Repository base: `vignatov/fabric-pq`, `main` at `9d5e90f1a`
  (`PQ4.0E.1: verify Fabric history before join approval`).
- Initial PR head **H0**: `13602e515ab55ef5d7779f204111394d96d871eb`.
  The pull-request workflows checked out synthetic merge **M0**:
  `b94e04d5bab8f13347a241652d5b57f178cac33c`, merging H0 into
  `9d5e90f1acaa804e5500d59ed00dbe0c84f7175d`. H0 and M0 below refer to
  these specific revisions, not later PR updates.
- Review follow-up head **H1**: `0f859eddb31c3d52e5b5c2c97c0970178eadc392`.
  Its pull-request workflows checked out synthetic merge **M1**:
  `b8b5f46cb5997967d1a1035b5e6ed4b3cc79ebb8`, merging H1 into the same
  base.
- The [current PR checks](https://github.com/vignatov/fabric-pq/pull/14/checks)
  provide the status of later runs. Compare their PR head and checkout
  revision with the current head and base before using them as final-head
  evidence; results for H0/M0 do not establish later-head results.
- Local environment: Linux/amd64 through WSL, Go 1.27.4, vendored
  dependencies, `GOFIPS140=off`. The following local runs are pre-commit
  working-tree evidence:

  ```text
  make pq-snapshot-acceptance
  PASS (race-enabled transport, provenance, enrollment, activation and core/peer tests; go vet)
  GOFIPS140=off GOFLAGS=-buildvcs=false go test -mod=vendor -race -count=1 ./internal/pkg/pqtransport/provisioning/... ./internal/pkg/pqtransport/enrollment/... ./internal/pkg/pqtransport/activation/... ./core/peer
  PASS
  GOFIPS140=off GOFLAGS=-buildvcs=false go vet -mod=vendor ./internal/pkg/pqtransport/provisioning/... ./internal/pkg/pqtransport/enrollment/... ./internal/pkg/pqtransport/activation/... ./core/peer
  PASS
  GOFIPS140=off GOFLAGS=-buildvcs=false go test -mod=vendor -race -count=1 -run '^TestPQ40EManagedOrdererNonGenesisPromotion$' ./orderer/common/multichannel
  PASS
  GOFIPS140=off GOFLAGS=-buildvcs=false go test -mod=vendor -race -count=1 -run '^TestPQ40D' ./orderer/common/multichannel
  PASS
  GOFIPS140=off GOFLAGS=-buildvcs=false go test -mod=vendor -race -count=1 ./orderer/consensus/etcdraft ./orderer/common/follower ./common/deliver
  PASS
  GOFIPS140=off GOFLAGS=-buildvcs=false go test -mod=vendor -race -count=1 -run '^TestPQ40E' ./orderer/common/multichannel
  PASS
  GOFIPS140=off GOFLAGS=-buildvcs=false go test -mod=vendor -race -count=1 -run '^TestPQ40E' ./orderer/common/broadcast
  PASS
  GOFIPS140=off GOFLAGS=-buildvcs=false go test -mod=vendor -race -count=1 -run '^TestPQ40E' ./orderer/common/cluster
  PASS
  GOFIPS140=off GOFLAGS=-buildvcs=false go test -mod=vendor -race -count=1 -run '^TestPQ40E' ./internal/pkg/comm
  PASS
  GOFIPS140=off GOFLAGS=-buildvcs=false go test -mod=vendor -race -count=1 -run '^TestPQ40E' ./internal/pkg/gateway
  PASS
  GOFIPS140=off GOFLAGS=-buildvcs=false go test -mod=vendor -race -count=1 -run '^TestPQ40E' ./core/peer
  PASS
  GOFIPS140=off GOFLAGS=-buildvcs=false go test -mod=vendor -race -count=1 -run '^TestPQ40E' ./core/chaincode ./core/chaincode/extcc ./gossip/comm ./gossip/privdata ./orderer/consensus/etcdraft
  PASS
  GOFIPS140=off GOFLAGS=-buildvcs=false go test -mod=vendor -race -count=1 ./core/endorser
  PASS
  GOFIPS140=off GOFLAGS=-buildvcs=false go test -mod=vendor -race -count=1 ./common/deliver ./core/ledger/snapshotgrpc ./orderer/common/channelparticipation
  PASS
  go build -mod=vendor -trimpath -o /tmp/pq40e2-assets-9bb18f69/orderer ./cmd/orderer
  PASS
  go build -mod=vendor -trimpath -o /tmp/pq40e2-assets-9bb18f69/peer ./cmd/peer
  PASS
  PQ40E_MANAGED_ORDERER=/tmp/pq40e2-assets-9bb18f69/orderer PQ40E_MANAGED_PEER=/tmp/pq40e2-assets-9bb18f69/peer go test -mod=vendor -race -count=1 ./cmd/pq-launcher
  PASS (systemd disposable-VM test skipped; this shared workspace is not a disposable VM)
  ```

The managed launcher binaries used for that test had SHA-256 peer
`22b239b7cbbefafe7f6dcf8bb25114d2668d4b0d0d246c137fa7dd49da222167` and
orderer `08d34275b876cf4352670b81906893a3484e28ee2098c695e70da21311e2cf1c`.

### Hosted evidence for H0/M0

- [Verify Build #45751350343](https://github.com/vignatov/fabric-pq/actions/runs/45751350343)
  ran on M0. PQ4.0 feasibility, PQ4.0B component, PQ4.0C, PQ4.0D,
  PQ4.0E, PQ4.0E.1 and PQ4.0E.2 focused jobs passed. Basic Checks passed
  its hosted license check but failed on the `modernize/mapsloop` lint
  finding; Unit Tests and all Integration Tests were skipped, not passed.
- The PQ4.0E job's
  [disposable-VM step](https://github.com/vignatov/fabric-pq/actions/runs/45751350343/job/139679624160)
  executed `TestPQ40EDisposableVMService` and passed. This is a managed
  service test, not a complete deployed snapshot-onboarding topology.
- The [PQ4.0E.2 job](https://github.com/vignatov/fabric-pq/actions/runs/45751350343/job/139679624506)
  passed snapshot acceptance and managed orderer promotion. Its built peer
  and orderer SHA-256 hashes were respectively
  `3ba38052100dcbb842e55466da7d33a46fc29cd91f128b09e367a52e74cec3a2` and
  `d9e95d9d41d1bd4815197f7ee4f6a36d89574ad0d1e1b9e12a4935dfe90b06bc`.
- [PQ3 isolated acceptance #45751350336](https://github.com/vignatov/fabric-pq/actions/runs/45751350336)
  passed on M0, including both profile runs and verification of their
  protected evidence packages.
- The [independent review](https://github.com/vignatov/fabric-pq/pull/14#pullrequestreview-6072623080)
  examined H0, supported the bounded design, and requested the changes and
  evidence described here. It did not independently run the code or audit a
  real exporter host.

### Hosted evidence for H1/M1

- [Verify Build #45805906460](https://github.com/vignatov/fabric-pq/actions/runs/45805906460)
  passed both repository-wide lint runs and all focused PQ4 jobs, including
  the snapshot and managed disposable-VM tests. Basic Checks subsequently
  failed because the orderer acquired a peer-ledger dependency and the
  generated metrics reference no longer matched. Unit and integration jobs
  were skipped. The later dependency fix keeps the snapshot filenames in the
  shared snapshot package and preserves the existing `kvledger` aliases;
  the metrics check passes locally and must be rerun on the current head.
- The [PQ4.0E.2 job](https://github.com/vignatov/fabric-pq/actions/runs/45805906460/job/139860964281)
  built peer and orderer binaries with SHA-256 hashes respectively
  `3789e24b189073ee25e12cfe04fef88ad08fcef4c3705eccc586ac54333e6b6f` and
  `5e6293bda4af0dad4ae8bd12819b326874465a74d00ca0ebbdf83fb2b2a7d778`.
- [PQ3 isolated acceptance #45805906462](https://github.com/vignatov/fabric-pq/actions/runs/45805906462)
  passed on M1. These results do not establish the outcome for a later head.

The native peer integration test generates a real Fabric snapshot and verifies
approved export, signed approval, protected import, recovery with retained
evidence, and fail-closed recovery when evidence is removed. Negative cases
cover wrong exporter key/identity, source-ledger and history/configuration
mismatches, payload and metadata changes, internally consistent recomputed
hashes without fresh exporter approval, missing/unexpected files, symlinks,
non-regular entries, wrong operator key, v1 anchor rejection, and a staged-byte
mutation before signing, which yields no approval. No private keys, TLS
secrets, or ledger payloads are included in public evidence.

## Security-property matrix

H0/M0 identifies the initial hosted evidence above. The same focused PQ4
and PQ3 jobs also passed at H1/M1, including the added v1 restart regression;
neither revision completed the full unit/integration matrix. These historical
results are not a substitute for the full current-head matrix. The snapshot
lifecycle test uses real Fabric ledger components in a test process, not a
separately deployed peer process.

| Category / security property | Implementation and test evidence | Evidence class | Tested commit | Outcome and remaining limitation |
| --- | --- | --- | --- | --- |
| Enrollment: signed manifest and protected history | Managed launcher and enrollment verification; [status](pq4.0e-status.md) | Native peer/orderer and disposable-VM tests | H0/M0 | Focused job passed; final-head rerun required |
| Enrollment: trusted launcher before readiness | `cmd/pq-launcher`; managed systemd test | Native peer/orderer and disposable-VM tests | H0/M0 | VM test passed; host enforcement outside the VM remains an assumption |
| Enrollment: policy/checkpoint authentication | `internal/pkg/pqtransport/activation`; enrollment tests | Component and native process tests | H0/M0 | Focused jobs passed; full privileged-host rollback is excluded |
| Enrollment: protected-to-baseline prohibition | Signed enrollment history and launcher | Native process and disposable-VM tests | H0/M0 | Focused jobs passed; production provisioning remains unqualified |
| Enrollment: missing state and restart | Protected registry and recovery paths | Native peer/orderer tests | H0/M0 | Focused jobs passed; final-head restart matrix required |
| Fabric provenance: trusted genesis and complete history | `provisioning.VerifyJoinHistory`; `provenance` package tests | Native Fabric ledger test | H0/M0 | PQ4.0E.1 job passed; final-head rerun required |
| Fabric provenance: historical signatures and predecessor configuration authorization | PQ4.0E.1 history verifier and tests | Native Fabric ledger test | H0/M0 | Job passed; live quorum/readiness is checked by native lifecycle, not offline replay |
| Fabric provenance: non-genesis approval and correct operator signer | `SignVerifiedOrdererJoinAnchor`; peer signing test below | Native process and ledger tests | H0/M0 | Focused promotion and snapshot tests passed; final-head rerun required |
| Fabric provenance: unsupported history and non-configuration target | History verifier negative tests | Native Fabric ledger test | H0/M0 | PQ4.0E.1 job passed; final-head rerun required |
| Snapshot: trusted exporter and source identity | `SnapshotExporterTrust`, signed evidence, exact trust checks; `TestPQ40ESignedNonGenesisSnapshotJoinAndRecovery` | Native Fabric ledger and peer-component test | H0/M0 | Focused job passed; actual exporter-to-ledger association remains an external trust assumption |
| Snapshot: metadata binding and complete payload integrity | `VerifySnapshotExport`, inventory and staged hash verification | Native Fabric ledger and peer-component test | H0/M0 | Focused job passed; compromised trusted exporter can sign false state |
| Snapshot: protected import and restart | `stageProtectedSnapshot`, durable evidence sidecar, `recoverProtectedSnapshot` | In-process native peer lifecycle test | H0/M0 | Missing evidence fails closed; deployed snapshot topology and final-head rerun remain pending |
| Service admission: peer endorsement, Gateway, gossip, discovery, Deliver and private data | Existing PQ4.0E service inventory/tests in [status](pq4.0e-status.md) | Component and native process tests | H0/M0 | Focused job passed; full final-head regression and external topology remain pending/deferred |
| Service admission: chaincode invocation and CCAAS | Existing lease and managed connection tests | Component and native process tests; distributed-network test not demonstrated | H0/M0 | Focused job passed; full deployed CCAAS topology remains out of scope |
| Service admission: orderer Broadcast, Raft and follower promotion | PQ4.0D native orderer tests and PQ4.0E.1 promotion tests | Native orderer tests | H0/M0 | Focused jobs passed; final-head rerun required |
| Service admission: participation administration | Existing strict admin and signed join tests | Native orderer tests | H0/M0 | Focused job and VM passed; full final-head evidence required |
| Activation: generation leases and staged configuration | PQ4.0C activation tests | Native peer/orderer tests | H0/M0 | PQ4.0C job passed; final-head rerun required |
| Activation: TLS-root publication and connection-cache retirement | PQ4.0C/E staged publication tests | Component and native process tests | H0/M0 | Focused jobs passed; final-head rerun required |
| Activation: interrupted commit and restart reconciliation | PQ4.0C crash matrix and recovery tests | Native Fabric ledger test | H0/M0 | PQ4.0C job passed; power-loss and privileged rollback are not demonstrated |
| Transport: selected strict profile, listener readiness and mTLS | PQ4.0E strict-listener tests | Component and native process tests | H0/M0 | Focused job passed; network-wide PQ4.0B compliance is not established |
| Transport: classical rejection | Existing strict TLS listener negative tests | Component and disposable-VM tests | H0/M0 | Focused tests passed; endpoint-wide and unsupported-binary proofs remain incomplete |
| Transport: administrative endpoints and shared-listener minimum policy | Existing service inventory and strict admin tests | Native process tests | H0/M0 | Focused job passed; network-wide/channel-capability enforcement is not demonstrated |
| Compatibility: baseline Fabric behavior | Baseline regression suites | Full unit and integration matrix | H0/M0 | Skipped after Basic Checks failed; full final-head Verify Build required |
| Compatibility: mixed-channel isolation | `core/peer/pq40e_mixed_channel_test.go` and full peer package test | In-process native peer tests | H0/M0 | Focused job passed; final-head CI required |
| Compatibility: v1 snapshot-joined peers | V2-only recovery and v1 rejection; [upgrade boundary](pq4.0e2-snapshot-provenance.md) | In-process native peer lifecycle test | H0/M0 for v1 import rejection; H1/M1 for restart regression | No supported in-place v1 migration; final-head restart test required |
| Compatibility: PQ3 isolated acceptance | PQ3 isolated acceptance workflow | Isolated hosted acceptance | H0/M0 | Passed; final-head rerun required |
| Overall development acceptance and independent review | Full matrix, trusted provisioning evidence and final-head review | Partially demonstrated | H0/M0 only | **INCOMPLETE — ADDITIONAL EVIDENCE REQUIRED** |

## Assumptions, limitations, and deferred work

The development trust boundary includes the independently authorized
exporter process, the integrity of its source ledger, the trusted
provisioning/operator signing authority, and the isolated host kernel and
filesystem used for staging. The exporter public key and expected source-ledger
identity are provisioner-controlled pins; they are not accepted from snapshot
metadata. The APIs authenticate matching claims but do not attest the actual
source ledger or exporter execution. A real independent pinning and controlled
exporter workflow has not been evidenced; see the
[trust and upgrade boundary](pq4.0e2-snapshot-provenance.md). A compromised
trusted exporter capable of authenticating false state is not detected by
metadata or payload hashes.

This report does not claim that Fabric history replay reconstructs world state,
that snapshot hashes prove arbitrary state correctness, or that production
deployment is certified. Production deployment remains **NOT CERTIFIED**.

PQ4.0B remains **INCOMPLETE**. `PactwayPQTransportV1`, network-wide transport
compliance, unsupported-binary capability enforcement, complete distributed
CCAAS acceptance, full post-quantum X.509-chain guarantees, and PQ4.1–PQ4.5
remain deferred. The H0 independent review is recorded above; review of
subsequent substantive changes and complete final-head evidence remain
required. Do not merge automatically.
