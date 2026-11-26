# PQ4.0E.2 trusted snapshot export

## Architecture review and assurance boundary

Fabric's native `kvledger` snapshot generator exports transaction IDs,
configuration history, public state and private-state hashes from the source
ledger. It emits `_snapshot_signable_metadata.json` with the channel, snapshot
height, last and previous block hashes, state database type, and a map of
payload filenames to raw SHA-256 hashes. It emits
`_snapshot_additional_metadata.json` with a hash of the signable metadata and
the last block commit hash. Native import checks the metadata hash and each
listed payload hash before loading the snapshot.

These hashes bind the imported bytes to the metadata, but the exporter itself
computes them from its local ledger and files. Fabric block-history
verification authenticates the configuration boundary, not the snapshot
world-state contents. Neither the native metadata nor replaying the block
history proves that arbitrary exported state was derived from that history.
State authenticity therefore depends on trusting the source ledger and the
exporter that accesses it.

PQ4.0E.1's registry-bound `provisioning.VerifyJoinHistory` remains the sole
history verifier. A separate exporter evidence signature is required in
addition to that verified result. The trusted provisioning boundary supplies
the exporter public-key pin, exporter identity, and expected source-ledger
identity from independently controlled configuration; none may be learned
solely from snapshot metadata or the evidence being verified. The export
evidence binds those identities to the network, channel, trusted genesis,
exact verified configuration boundary and digest, source-history identity,
native metadata byte hashes, complete payload inventory, and
`pactway-pq-tls-v1` profile.

Before operator approval, the provisioner validates the exporter signature,
metadata and complete directory inventory, then stages the exact bytes into a
private directory and verifies hashes while copying. The operator-signed peer
anchor binds the staged snapshot's metadata hashes and export-evidence digest,
exporter identity, and source-ledger identity. The package carries the
authenticated evidence sidecar. The protected importer verifies it against
the signed anchor, stages only the enumerated native files, and retains the
evidence durably for restart recovery. Missing or conflicting evidence keeps
the protected channel closed.

Managed protected peers continue to reject their normal snapshot-export RPCs.
Snapshot creation for protected onboarding must use a separately authorized,
offline or isolated provisioning workflow; this design adds no remote export
bypass.

## Assumptions and limitations

The development assurance trusts the independently authorized exporter
process, the source ledger's integrity, the trusted provisioner and operator
signing authority, and the host kernel/filesystem boundary used for isolated
staging. A compromised trusted exporter capable of signing false state is not
detectable from metadata or file hashes. This workflow does not provide a
cryptographic commitment from Fabric block history to arbitrary world state,
nor does it claim that history replay reconstructs that state.

Physical deployment, production key custody, production operator procedures,
PQ4.0B network-wide transport enforcement, `PactwayPQTransportV1`, and
distributed CCAAS acceptance remain outside this milestone.

## Implemented workflow

The exporter emits canonical, versioned `fabric-pq/snapshot-export/v1`
evidence signed over the complete payload with the
`fabric-pq/snapshot-export/v1` domain and a NUL separator. The evidence
contains a fresh evidence identifier, the exact source/history boundary,
hashes of both raw native metadata files and the complete payload filename /
SHA-256 inventory. The exporter private key stays in the isolated exporter
environment.

The provisioner constructs `SnapshotExporterTrust` from its independent
exporter-key pin, exporter identity and expected source-ledger identity. A
successful `provisioning.VerifyJoinHistory` result and this trust pin are both
required to obtain the opaque `VerifiedSnapshotExport` token. The only peer
snapshot anchor signer accepts that token, rechecks its staged metadata and
payload bytes immediately before signing, and uses the versioned
`fabric-pq/peer-snapshot/v2` domain. The signature binds the evidence digest,
exporter identity, source-ledger identity and approved exporter public key.
There is no v1 peer-anchor fallback.

The runtime verifies the sidecar against the v2 anchor, stages exactly the
listed native files, and writes the authenticated evidence to a durable
channel-bound sidecar in protected state. Activation-store recovery recognizes
only that specific `.export` record suffix and still binds it to an
authenticated channel. Snapshot recovery requires and re-verifies the same
evidence. The normal protected snapshot-export RPC restrictions are unchanged.

## Focused validation

The dedicated `make pq-snapshot-acceptance` target runs race-enabled tests for
the transport/provenance/enrollment packages and native peer suite, followed
by `go vet` on those packages. On this working tree, focused race tests and
vet passed on Linux/amd64 with Go 1.27.4 and vendored dependencies. The exact
tested source SHA and CI/binary provenance are pending a final committed head;
see the [acceptance report](pq4.0e2-acceptance.md). This is not a full
PQ4.0E development-gate decision.
