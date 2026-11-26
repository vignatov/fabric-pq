# PQ4.0E.1 Fabric provenance verification

**Status: development implementation; full acceptance and independent review
pending.** This helper does not certify production deployment and does not
close the PQ4.0B network-enforcement gate.

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
   - `provisioning.SignVerifiedPeerSnapshotAnchor` for the peer
     `fabric-pq/peer-snapshot/v1` domain, with the exact native signable and
     additional metadata bytes.
6. Provision the target configuration block alongside the approved anchor
   where the existing enrollment contract requires it. The receiving peer
   still verifies metadata and every snapshot file hash before import.

   For snapshots, the trusted provisioner must independently trust that the
   exporter created the snapshot state from the verified channel history and
   must validate the exported files against the metadata before signing.
   `SignVerifiedPeerSnapshotAnchor` checks the metadata boundary and digest
   syntax only; it neither reads the payload files nor proves their state
   provenance. A maliciously replaced payload and recomputed metadata can
   therefore be signed if the provisioner fails to establish this separate
   trusted-exporter assumption. Import-time hash checks establish integrity
   against the signed metadata, not authenticity of the exported state.

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
Linux race-enabled integration tests now exercise registry-bound history
verification and gated anchor issuance through native managed orderer
promotion and peer snapshot import/recovery. The exact race and vet commands
passed locally in a disposable Linux container on the initial review head.
The hosted PQ4.0E.1 job and PQ4.0E disposable-VM step passed on commit
`1b47d8bf0`, but Basic Checks failed and full unit/integration checks were
skipped. Final-head hosted CI, disposable-VM evidence and independent review
remain required before PQ4.0E development acceptance can be declared complete.
