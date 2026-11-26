# PQ4.0E development acceptance report

**Decision: INCOMPLETE — ADDITIONAL EVIDENCE REQUIRED**

PQ4.0E.2 now implements an authenticated snapshot-export path and has focused
native-ledger, protected-import and recovery coverage. This report does not
self-certify the complete PQ4.0E gate. The full Verify Build, required
disposable-VM rerun, final-head provenance and independent review have not yet
been completed for this change.

## Provenance and tested head

- Repository base: `vignatov/fabric-pq`, `main` at `9d5e90f1a`
  (`PQ4.0E.1: verify Fabric history before join approval`).
- PQ4.0E.2 implementation: local PR branch; the hosted CI run/job ID and
  final binary hashes are pending. The local runs below are working-tree
  evidence from before commit creation.
- Local environment: Linux/amd64 through WSL, Go 1.27.4, vendored
  dependencies, `GOFIPS140=off`.
- Focused commands and results:

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

`Current-head commit` means the exact source SHA exercised by evidence. Until
the changes are committed and CI reruns on that exact head, each new result is
local evidence only. Historical evidence remains identified in the linked
PQ4 reports and does not stand in for a final-head rerun.

| Category / security property | Implementation and test evidence | Evidence class | Tested commit | Outcome and remaining limitation |
| --- | --- | --- | --- | --- |
| Enrollment: signed manifest and protected history | Managed launcher and enrollment verification; prior PQ4.0E tests in [status](pq4.0e-status.md) | Native peer/orderer process test; disposable-VM test (historical) | Historical heads in linked report; current head pending | Existing bounded evidence; final-head rerun pending |
| Enrollment: trusted launcher before readiness | `cmd/pq-launcher`; managed systemd test | Native peer/orderer process test; disposable-VM test (historical) | Current head pending | Host service-manager enforcement outside the test VM remains an assumption |
| Enrollment: policy/checkpoint authentication | `internal/pkg/pqtransport/activation`; enrollment integration tests | Component test; native process test (historical) | Current head pending | Full privileged-host rollback is excluded |
| Enrollment: protected-to-baseline prohibition | Signed enrollment history and launcher | Native process test; disposable-VM test (historical) | Current head pending | Production provisioning boundary remains unqualified |
| Enrollment: missing state and restart | Protected registry and recovery paths | Native peer/orderer process test (historical) | Current head pending | Final-head restart matrix pending |
| Fabric provenance: trusted genesis and complete history | `provisioning.VerifyJoinHistory`; `provenance` package tests | Native Fabric ledger test (historical) | `9d5e90f1a` is base only; final head pending | Re-run exact final-head tests and record hosted provenance |
| Fabric provenance: historical signatures and predecessor configuration authorization | PQ4.0E.1 history verifier and tests | Native Fabric ledger test (historical) | Current head pending | Live quorum/readiness is checked by native lifecycle, not offline replay |
| Fabric provenance: non-genesis approval and correct operator signer | `SignVerifiedOrdererJoinAnchor`; peer signing test below | Native process test; native ledger test | Current head pending | Orderer process proof must be rerun |
| Fabric provenance: unsupported history and non-configuration target | History verifier negative tests | Native Fabric ledger test (historical) | Current head pending | Final-head rerun pending |
| Snapshot: trusted exporter and source identity | `SnapshotExporterTrust`, signed evidence, exact trust checks; `TestPQ40ESignedNonGenesisSnapshotJoinAndRecovery` | Native Fabric ledger test | Local PR branch (pre-commit working tree) | Focused test passes; external exporter key custody is a trusted-environment assumption |
| Snapshot: metadata binding and complete payload integrity | `VerifySnapshotExport`, inventory and staged hash verification | Native Fabric ledger test | Local PR branch (pre-commit working tree) | Focused positive and negative cases pass; compromised trusted exporter can sign false state |
| Snapshot: protected import and restart | `stageProtectedSnapshot`, durable evidence sidecar, `recoverProtectedSnapshot` | Native peer process test | Local PR branch (pre-commit working tree) | Evidence missing after restart fails closed; final-head CI/VM rerun pending |
| Service admission: peer endorsement, Gateway, gossip, discovery, Deliver and private data | Existing PQ4.0E service inventory/tests in [status](pq4.0e-status.md) | Native peer process test (historical) | Current head pending | Full final-head regression and external topology remain pending/deferred |
| Service admission: chaincode invocation and CCAAS | Existing lease and managed connection tests | Native peer process test (historical); distributed-network test not demonstrated | Current head pending | Full deployed CCAAS topology remains out of scope for PQ4.0E.2 |
| Service admission: orderer Broadcast, Raft and follower promotion | PQ4.0D native orderer tests and PQ4.0E.1 promotion tests | Native orderer process test (historical) | Current head pending | Must rerun Raft quarantine/replay and managed promotion suites |
| Service admission: participation administration | Existing strict admin and signed join tests | Native orderer process test (historical) | Current head pending | Final-head VM and full acceptance evidence pending |
| Activation: generation leases and staged configuration | PQ4.0C activation tests | Native peer/orderer process test (historical) | Current head pending | Final-head activation proof pending |
| Activation: TLS-root publication and connection-cache retirement | PQ4.0C/E staged publication tests | Component test; native process test (historical) | Current head pending | Re-run failure and restart reconciliation suites |
| Activation: interrupted commit and restart reconciliation | PQ4.0C crash matrix and recovery tests | Native Fabric ledger test (historical) | Current head pending | Power-loss and privileged rollback are not demonstrated |
| Transport: selected strict profile, listener readiness and mTLS | PQ4.0E strict-listener tests | Component test; native process test (historical) | Current head pending | Does not establish network-wide PQ4.0B transport compliance |
| Transport: classical rejection | Existing strict TLS listener negative tests | Component test (historical) | Current head pending | Endpoint-wide and unsupported-binary proofs remain incomplete |
| Transport: administrative endpoints and shared-listener minimum policy | Existing service inventory and strict admin tests | Native process test (historical) | Current head pending | Network-wide/channel-capability enforcement is not demonstrated |
| Compatibility: baseline Fabric behavior | Baseline regression suites | Native Fabric ledger test (historical) | Current head pending | Full Verify Build required |
| Compatibility: mixed-channel isolation | `core/peer/pq40e_mixed_channel_test.go` and full peer package test | Native peer process test | Local PR branch (pre-commit working tree) | Focused race suite passes; exact final-head CI pending |
| Compatibility: PQ3 isolated acceptance | Prior workflow evidence in [PQ4.0E status](pq4.0e-status.md) | Disposable-VM / isolated acceptance (historical) | Prior workflow commit recorded in linked report | Must rerun PQ3 isolated acceptance on final head |
| Overall development acceptance and independent review | Full matrix and final-head workflow not yet complete | Not yet demonstrated | No final-head CI provenance | **INCOMPLETE — ADDITIONAL EVIDENCE REQUIRED** |

## Assumptions, limitations, and deferred work

The development trust boundary includes the independently authorized
exporter process, the integrity of its source ledger, the trusted
provisioning/operator signing authority, and the isolated host kernel and
filesystem used for staging. The exporter public key and expected source-ledger
identity are provisioner-controlled pins; they are not accepted from snapshot
metadata. A compromised trusted exporter capable of authenticating false
state is not detected by metadata or payload hashes.

This report does not claim that Fabric history replay reconstructs world state,
that snapshot hashes prove arbitrary state correctness, or that production
deployment is certified. Production deployment remains **NOT CERTIFIED**.

PQ4.0B remains **INCOMPLETE**. `PactwayPQTransportV1`, network-wide transport
compliance, unsupported-binary capability enforcement, complete distributed
CCAAS acceptance, full post-quantum X.509-chain guarantees, and PQ4.1–PQ4.5
remain deferred. No independent review is claimed; request review before
merging. Do not merge automatically.
