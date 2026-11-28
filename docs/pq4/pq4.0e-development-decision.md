# PQ4.0E development gate decision

**Accepted: PQ4.0E COMPLETE (DEVELOPMENT).** The [architecture/security
assessment](https://github.com/vignatov/fabric-pq/pull/17#issuecomment-7231283221)
explicitly accepted the bounded decision at PR #17 head
`37c5c60f9bfb63e368f4c34e876f61dc32189ff0` and requested this recording
update. It is a conversation comment posted by the authenticated PR author,
who could not submit a formal self-approval; the comment describes the
assessment as independent. It assesses the evidence and does not claim to
have re-executed the VM. This record becomes effective on `main` when merged;
the [authoritative status](pq4.0e-status.md) on `main` remains incomplete
until then.

## Evidence inventory

The implementation reviewed in [PR #15](https://github.com/vignatov/fabric-pq/pull/15)
is head `14b8876eba4ac544db6bff9bb476bd136a95e20d`; its tree matches squash
commit `b198558ee72330a4074eaff944a91c7362fa7f61`. The push run checked out
that head; the PR run used a synthetic merge. These results do not establish
security of later upstream changes. The [merged PR #16](https://github.com/vignatov/fabric-pq/pull/16)
reconciled the evidence at merge commit `4c75149e18248a898e6d1a224a63c25d9cba21fe`.

| Evidence | Scope and outcome |
| --- | --- |
| PR #15 Verify Build [PR attempt 2](https://github.com/vignatov/fabric-pq/actions/runs/45887599318/attempts/2), [push attempt 2](https://github.com/vignatov/fabric-pq/actions/runs/45887591040/attempts/2) | Both reported 19/19 jobs successful, including unit, nine integration groups, Basic Checks and focused PQ4.0C/D/E/E.1/E.2/E.3 and PQ4.0B component checks. First attempts timed out in [private-data historical-data](https://github.com/vignatov/fabric-pq/actions/runs/45887599318/job/140145263575) and [PKCS#11 startup](https://github.com/vignatov/fabric-pq/actions/runs/45887591040/job/140147609103), respectively; both passed on retry. See the [retry record](https://github.com/vignatov/fabric-pq/pull/15#issuecomment-7205183507). |
| PR #15 PQ3 [PR](https://github.com/vignatov/fabric-pq/actions/runs/45887599194), [push](https://github.com/vignatov/fabric-pq/actions/runs/45887591064) | Both isolated-network runs passed on attempt 1. |
| Ubuntu VM, snapshot and provisioning | The [property matrix and artifact inventory](pq4.0e3-development-gate.md) identify hosted Ubuntu 24.04 jobs, disposable service-manager VM, separate identities, controlled Ledger A/B export, signed authorization and execution record, snapshot inventory, protected import, fresh-process recovery and baseline continuity. The [snapshot report](pq4.0e2-acceptance.md) and [provisioning guide](pq4.0e3-provisioning.md) describe their respective boundaries. The [PR #15 artifact record](https://github.com/vignatov/fabric-pq/pull/15#issuecomment-7201333814) reports payload verification; the [implementation review](https://github.com/vignatov/fabric-pq/pull/15#pullrequestreview-6081072626) inspected source and hosted logs. |
| PR #16 reconciliation | Its [second review](https://github.com/vignatov/fabric-pq/pull/16#issuecomment-7223561423) supports bounded development completion after a separate decision on `main`, and identifies documentation-branch [Verify Build](https://github.com/vignatov/fabric-pq/actions/runs/46015489267) (19 jobs) and [PQ3](https://github.com/vignatov/fabric-pq/actions/runs/46015489026) successes. It is a conversation comment because the authenticated PR author could not submit a self-approval review. These checks do not replace PR #15 implementation evidence. |

## Accepted development scope

The demonstration trusts the privileged provisioner and service manager,
authorized test-harness exporter, and Linux kernel. The signed execution record
reflects the provisioner's observations; history replay, signatures and hashes
do not independently cryptographically attest arbitrary ledger world state.
The evidence does not prove security against privileged-host compromise or
total rollback of protected state, or certify production deployment or key
custody. Existing v2 approvals lacking mandatory pre-export authorization and
execution proof fail closed; there is no migration or compatibility fallback
for those old v2 snapshots. See the [provisioning boundary](pq4.0e3-provisioning.md)
and [snapshot provenance](pq4.0e2-snapshot-provenance.md). Distributed CCAAS
and production topology are also outside this decision.

PQ4.0B network-wide enforcement remains INCOMPLETE. This decision does not
authorize PQ4.1. PQ4.0B.1 remains blocked until this accepted decision is
recorded on `main`; only then is PQ4.0B.1 authorized.
