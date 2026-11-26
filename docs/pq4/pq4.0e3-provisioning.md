# PQ4.0E.3 controlled provisioning boundary

## Decision

The development workflow uses an independently authenticated, versioned
authorization created before snapshot export. It pins the network, channel,
exporter identity and ML-DSA-65 key, source-ledger identity and canonical
ledger-directory path, trusted genesis, verified history and configuration
boundary, transport profile, and approval generation.

The authorization is signed under the
`fabric-pq/exporter-authorization/v1` domain by the provisioning authority.
The verifier receives the authority identity and public key from outside the
authorization package. Exporter or snapshot evidence cannot establish or
replace those trust pins. `VerifiedExporterAuthorization.SnapshotExporterTrust`
also requires the registry-bound `VerifiedJoinHistory` result and rejects an
authorization that conflicts with its network, channel, genesis, history,
profile, configuration or snapshot boundary.

## Source-ledger association

Fabric's native ledger manager opens a ledger by channel identifier and
generates the snapshot from that opened ledger. The native API does not
cryptographically attest the physical source-ledger directory. This workflow
therefore treats the canonical source-ledger directory as an externally
controlled provisioning identity, not as a Fabric proof.

The authorization pins that path before export. The controlled exporter
authenticates the authorization, rejects a different source-path override,
checks that the authorized directory exists and does not resolve through a
symlink, opens the authorized native ledger, checks the exact authorized
configuration block, and requests native snapshot generation. The disposable
Ubuntu test creates a second valid ledger at a different path, demonstrates
that the exporter identity cannot read it, and rejects an attempt to substitute
its path while claiming the approved source. The root-controlled execution
record links the invocation to the authorization digest and the independently
verified native snapshot.

The test demonstrates filesystem and process controls under a privileged
provisioner and trusted kernel. The ledger path and audit record are not
cryptographic attestations of world-state correctness. A compromised trusted
exporter with access to its approved ledger and signing key can still sign
false state.

## Trust domains and execution

- **Provisioning authority:** independently pins and signs authorization,
  verifies exporter evidence and registry-bound Fabric history, privately
  stages exact snapshot bytes, and signs the existing v2 peer snapshot anchor.
  Authority and operator signing keys remain outside exporter and importer
  access.
- **Snapshot exporter:** runs under a dedicated Linux identity, can access
  only the authorized source ledger and its export destination, and uses its
  separately pinned ML-DSA-65 key. It cannot modify authorization pins or read
  the operator or provisioning-authority private keys.
- **Protected importing peer:** runs under a separate Linux identity and uses
  the existing v2 anchor verification, protected snapshot import, retained
  evidence recovery, and readiness gates. It cannot modify the pre-existing
  exporter authorization or read the provisioning authority's private key.

The acceptance test uses an Ubuntu 24.04 GitHub-hosted job as the disposable
VM boundary and distinct OS users for exporter and importer execution. The
test binary invokes Fabric's native ledger manager for source access and the
existing peer snapshot-import path for protected admission; it does not claim
that process separation protects against privileged-host or kernel compromise.
The import test restarts the peer process and confirms protected readiness and
baseline-ledger continuity.

## Evidence and retained artifacts

The authority writes the operation record after the controlled exporter exits;
it records the exact invocation, executable digest, authorization digest,
selected source path and identity, channel and snapshot boundary. The verifier
then checks that record against the authorization and the native signed
evidence. The deterministic non-secret acceptance manifest links:

- exact checkout commit and CI workflow/job/run identifiers;
- exporter/importer test-binary digests;
- authorization identity/digest and exporter key fingerprint;
- source-ledger identity/path and controlled invocation;
- trusted genesis and verified history identities;
- snapshot block/configuration boundary, signed evidence and inventory digests;
- signed v2 join-anchor digest; and
- import, restart recovery, and baseline continuity results.

Only the manifest is retained as a CI artifact. Private signing keys, TLS
secrets, and ledger payloads stay inside the disposable VM. The protected
staging and v2 approval remain the existing `VerifySnapshotExport` and
`SignVerifiedPeerSnapshotAnchor` path; no alternate approval API is added.

## Scope and limitations

This workflow preserves registry-bound Fabric-history verification, exact
snapshot inventory verification, private staging, v2-only approval, and
fail-closed import/recovery. It does not prove arbitrary world-state
correctness, resist a fully privileged-host compromise or total host-state
rollback, enable remote protected snapshot export, or authorize v1 migration.
Production provisioning and PQ4.0B network enforcement remain separate gates.
Overall PQ4.0E development acceptance remains pending final-head CI evidence
and independent review.
