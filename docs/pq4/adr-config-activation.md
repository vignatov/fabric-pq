# ADR: PQ transport policy and Fabric configuration activation

**Status: proposed for architecture review; no activation design approved.**
**Scope:** peer/orderer channel configuration updates and local PQ transport
checkpoints. This ADR does not authorize implementation of
`PactwayPQTransportV1`.

## Context

PQ4 requires a channel's authenticated transport requirement and the node's
protected local policy checkpoint to advance consistently. Fabric currently
publishes configuration resources before durable ledger append:

- The peer's `Channel.Apply` validates a config envelope, creates and validates
  a bundle, then calls `BundleSource.Update`. Config transaction validation
  calls `Apply` before the block is committed. `LedgerCommitter.CommitLegacy`
  invokes its post-commit callback only after the ledger commit succeeds.
- The orderer's `BlockWriter.WriteConfigBlock` validates and builds the
  candidate bundle, updates `support`, then calls `WriteBlockSync`. During
  block writing, metadata derives its last-config sequence from the active
  support bundle. Moving `support.Update` after append without changing that
  metadata path can write stale config-sequence metadata.

Consequently, a post-commit-only checkpoint callback cannot prevent
pre-commit publication. The ledger append and a separate protected policy
store also do not share an atomic transaction.

## Proposed protocol for review

This is a candidate for prototyping only after architecture approval:

1. **Authenticate and prepare before publication.** At the peer's
   `Channel.Apply` boundary and the orderer's
   `BlockWriter.WriteConfigBlock` boundary, obtain the channel ID from the
   validated config envelope, use Fabric's existing config authorization and
   validation, and compare the exact candidate config sequence and digest
   against a separately operator-signed transition. Persist and flush a
   `PREPARED` journal record containing the channel, block/config identity,
   previous and candidate checkpoint versions/digests, and transition
   authorization before publishing candidate resources. Do not treat a
   signature alone as Fabric authorization.
2. **Serialize and gate channel use.** Hold the channel's existing config
   serialization boundary while preparing, committing and activating. Once
   prepared, block channel admissions/operations that could observe a mixed
   config/checkpoint state. The peer implementation must account for
   endorsement, delivery, gossip, private-data, and all readers of the bundle.
   The orderer implementation must account for consensus leader and follower
   paths and the signing identity/metadata needed to write the config block.
3. **Commit, then activate and checkpoint.** Append the authenticated config
   block to the ledger. Only after durable success, atomically mark the journal
   committed, advance the protected local checkpoint, publish the candidate
   resources, and reopen admissions. The orderer must preserve the correct
   candidate last-config sequence and block signature while avoiding
   pre-append publication; this requires an explicit candidate-sequence
   metadata path or another reviewed mechanism, not merely moving
   `support.Update`.
4. **Recover before readiness.** Before listeners, channel services, or
   participation become ready, read the durable journal and committed ledger
   configuration. If the candidate block is committed and matches `PREPARED`,
   complete checkpoint advancement and activation. If it is not committed,
   discard/abort the preparation and retain the prior policy. If the ledger,
   journal, signatures, or checkpoint conflict, keep the affected channel
   closed and fail readiness; never silently roll back to an older serving
   state. Crash injection must cover each journal fsync, ledger append, state
   update and resource publication boundary.

These are design obligations, not demonstrated properties. In particular,
the exact peer and orderer lock scope, atomic checkpoint write, block-signing
semantics, and safe orderer metadata construction remain unresolved.

## Required review and falsification tests

Before implementing channel capability or persistent policy integration,
architecture review must approve a concrete design and ownership of the
journal. A prototype must then demonstrate:

- authenticated channel creation/join and normal non-weakening updates;
- rejection of missing, stale, conflicting, unauthorized, or weakening
  transitions before any candidate bundle is visible;
- leader, follower and concurrent channel-use behavior;
- crashes before and after each durable write, followed by restart that either
  completes the authorized transition or fails closed;
- ledger config sequence, last-config metadata, block signatures and
  checkpoint agree after each recovery case; and
- an old binary's behavior is tested only after the actual capability is
  supported and advertised.

The current component verifier does not provide any of these lifecycle
guarantees. Until this review and prototype pass, the PQ4.0B channel-binding
and transition-recovery gates remain **INCOMPLETE**.
