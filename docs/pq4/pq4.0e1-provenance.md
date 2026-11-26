# PQ4.0E.1 Fabric provenance verification

**Status: bounded development implementation reviewed as acceptable for merge
at `0c3e9db3402dbc87d536d0959442266f4c75c256`.** Full PQ4.0E acceptance,
independent snapshot-state provenance and production deployment certification
remain incomplete; this helper does not close the PQ4.0B network-enforcement
gate.

## Trust and verification boundary

Use the authenticated protected registry as the source of the channel's
independently provisioned genesis block and local policy/checkpoint. Do not
select a genesis trust anchor from the candidate join block or history.
`provisioning.VerifyJoinHistory` obtains the genesis block from the registry,
then verifies a complete sequence from block zero through the requested
non-genesis configuration block.

Registry-bound history verification checks each block's channel identity,
consecutive number, previous-header link, data hash, signed `LAST_CONFIG`
index and duplicate `LAST_CONFIG` metadata. Fabric's native block-verification assistant validates
block signatures under the historical `BlockValidation` policy. Every
configuration update is authorized against the preceding configuration using
Fabric's `ConfigtxValidator`, then checked using native bundle compatibility
validation. Sequence progression and historical policy identities are
recorded. The target configuration's deterministic digest and sequence must
match the authenticated local policy binding for the same network, node,
channel and `pactway-pq-tls-v1` profile.

Only Raft channels are supported; other consensus types, including those
with empty metadata, and consensus-type transitions fail closed. Native
consensus-metadata validation checks the Raft config metadata and TLS
certificates against the applicable orderer MSP roots. Static history
verification cannot prove that a live quorum or the intended snapshot voter
set is ready. Participation
followers and snapshot import must still pass their existing native membership,
replay and readiness checks.

## Provisioner helper flow

The helper APIs are in `internal/pkg/pqtransport/provenance`,
`internal/pkg/pqtransport/provisioning` and
`internal/pkg/pqtransport/enrollment`:

1. Load and authenticate the signed enrollment evidence, then open the
   protected registry and local checkpoint.
2. Supply the immutable block sequence beginning at that registry's genesis
   and ending at the exact intended configuration block.
3. Call `provisioning.VerifyJoinHistory(registry, channel, history, target,
   crypto)`. On any error, do not issue a join anchor. Only its registry-bound
   result is eligible for signing. The generic
   `provenance.VerifyHistoryWithReport` is diagnostic only and does not
   establish trust in caller-supplied genesis or policy.
4. Preserve `verified.Report()` as deterministic, non-secret verification
   evidence. It includes the source-history identity, trusted genesis,
   verified range, target block/configuration, applicable historical policy
   identities, transport profile and exact target join-anchor digest.
5. Issue only the matching approval:
   - `provisioning.SignVerifiedOrdererJoinAnchor` for the orderer
     `fabric-pq/orderer-join/v1` domain.
   - For a peer snapshot, the authorized exporter signs
     `provisioning.SignSnapshotExportEvidence` after native export. The
     trusted provisioner verifies an independently signed exporter
     authorization and controlled execution record, derives the exporter trust
     pin, and calls `provisioning.VerifySnapshotExport`. It passes the staged
     result and both verified proofs to
     `provisioning.SignVerifiedPeerSnapshotAnchor`. This issues the versioned
     `fabric-pq/peer-snapshot/v2` approval.
6. Provision the target configuration block, v2 anchor, and authenticated
   `_pactway_snapshot_export_evidence.json` sidecar with the native snapshot.
   The peer verifies the evidence and exact file inventory, stages only
   approved payload files, and retains the sidecar for restart recovery.

The exporter identity and source-ledger identity are not accepted solely
because they appear in the evidence. The v2 operator anchor binds the
evidence digest, exporter identity, source-ledger identity and approved
exporter public key. The earlier helper that accepted raw metadata bytes is
not retained as an alternate onboarding path. A self-consistent payload and
recomputed native metadata hashes without fresh exporter authentication are
rejected. This proves an authenticated exporter approval, not state correctness
against a compromised exporter; arbitrary world-state correctness is not
cryptographically derived from Fabric history. The claim that the exporter
actually read the approved source ledger depends on the separately controlled
provisioning workflow. PQ4.0E.3 demonstrates pre-export authorization and
controlled native access to the authorized ledger path; see the
[provisioning-boundary decision](pq4.0e3-provisioning.md) and
[source-ledger trust and upgrade boundary](pq4.0e2-snapshot-provenance.md).

The signing helpers require the private key corresponding to the authenticated
policy signer. Keep that key in the external trusted provisioning authority;
never copy it into channel packages, peer/orderer runtime state, or retained
test artifacts. The helper does not write or distribute private keys.

The report is not itself an authorization unless the operator separately
signs and retains it under an approved evidence policy. A successful report
does not replace the operator-signed join anchor, and the operator signature
does not replace Fabric-history verification.

## Current acceptance boundary

Focused tests exercise Fabric-generated configuration updates, Fabric MSP
signatures, historical policy rejection, hash-link failures, incomplete
history, wrong genesis/channel, unauthorized config transitions, local policy
mismatch, unsupported consensus and non-configuration targets, and
registry-bound anchor issuance gating.
Linux race-enabled integration tests exercise registry-bound history
verification and gated anchor issuance through native managed orderer
promotion and peer snapshot import/recovery.

On commit `0c3e9db3402dbc87d536d0959442266f4c75c256`, [Verify Build
run 45728658438](https://github.com/vignatov/fabric-pq/actions/runs/45728658438)
passed all 17 jobs, including unit tests, all nine integration groups, focused
PQ4.0E.1 tests and the PQ4.0E disposable systemd-VM proof.
[PQ3 isolated acceptance run
45728658316](https://github.com/vignatov/fabric-pq/actions/runs/45728658316)
also passed. The first PR unit-test attempt hit a timeout-test failure in
unchanged Gateway code; the same-head push unit run and PR rerun both passed.
The independent review accepts this bounded implementation for merge, subject
to DCO sign-off. These results do not complete PQ4.0E or PQ4.0B, prove
independent snapshot-state provenance, or certify production deployment.
