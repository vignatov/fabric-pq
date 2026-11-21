# PQ4.0 transport-policy enforcement review

Status: **NOT PROVEN; architecture decision and PQ4.1 are blocked**. This
document records the candidates and evidence available so far, not an
approved implementation or a statement that PQ4 endpoints exist.

## Candidates

| Candidate | Strength | Unresolved security gap |
| --- | --- | --- |
| Authenticated channel capability alone | Authenticated version and unsupported-binary rejection can be tied to channel configuration. | The TLS handshake occurs before a channel is identified or its configuration can be read; admin and CCAAS may have no channel context. This candidate alone cannot establish the required pre-handshake protection. |
| Trusted, versioned node/network transport policy alone | Can govern bootstrap, all listener and client construction, CCAAS and admin before a channel is known. | Needs an authenticated trust anchor, provisioning and rollback protection, agreement with network/channel requirements, and a way to prevent old binaries from silently participating. A local environment flag by itself is insufficient. |
| Layered node policy and authenticated channel requirement | Can bind a pre-handshake minimum to a channel's authenticated requirement and cover non-channel paths. | The binding, bootstrap trust, downgrade-resistant updates and old-binary behavior remain unimplemented and unproved. It is a candidate for review, not a selected architecture. |

Do not treat the existing `PactwayHybridCertificatePactwayV1` enrollment
capability as a transport capability. If a distinct transport capability is
chosen, its precise semantics, fresh-genesis behavior and removal protection
must be implemented and tested; a capability by itself does not control TLS.

## Trust boundaries and required design decisions

- Define who provisions and authenticates a bootstrap policy, its trust
  anchors, network identity, version and anti-rollback state; specify what
  happens before a peer joins and before the orderer receives its genesis.
- Bind authenticated channel requirements to that policy and fail closed on
  missing, stale or conflicting state. Specify the attacker and the
  consequences of an administrator or host with access to local keys,
  configuration, binaries or persistent rollback state.
- Decide whether mixed-security channels require separate listeners or the
  strongest policy across a shared listener. Prove that a weaker channel
  cannot create a path into a PQ4-required channel.
- Enforce and authenticate policy for both peer-to-CCAAS connections,
  including the independently constructed chaincode server; avoid
  distributing private TLS client keys in chaincode packages.
- Cover admin HTTPS and `osnadmin`, discovery, gossip, Gateway, events,
  delivery, Raft, connection pools, dynamic trust/certificate updates,
  restart, rotation and configuration reload. See the
  [coverage matrix](transport-coverage.md) for concrete constructors.
- Prevent authorized channel updates and restarts from weakening PQ4 and
  define the behavior of upstream and older Pactway binaries using real
  peer and orderer binaries.

## Feasibility evidence and gaps

The [standalone and comm tests](validation-and-evidence.md) demonstrate
native hybrid/ML-DSA handshakes and cause-specific TLS rejections in
controlled configurations. They also show that the current Fabric comm
server accepts classical-only key exchange. The test-only additional
certificate check does not authenticate a network policy or enforce it in
Fabric.

The following mandatory proofs are **not yet available**:

1. Missing, stale, conflicting or weakened trusted policy fails closed before
   all required listeners and connections.
2. Node and authenticated channel requirements cannot disagree silently;
   authorized channel updates cannot downgrade the network.
3. Unsupported binaries cannot participate via classical transport.
4. Shared listeners and CCAAS, admin and other non-channel endpoints enforce
   the same approved policy.
5. A committed transaction is considered PQ4-compliant only when all its
   required communication paths have independently reviewable handshake and
   authentication evidence.

No positive or negative policy-integration test, unsupported-binary test, or
network-wide PQ4 transaction has been run. A design assertion or the
standalone TLS success does not satisfy those tests. The additional Go
`VerifyConnection` feasibility experiment rejects classical leaf keys only
after normal chain validation; it does not address authenticated policy,
root/chain profile requirements or the selection of an implementation.

## Review and stop

Do not begin PQ4.1 or claim network-wide post-quantum transport until the
remaining enforcement feasibility work and architecture review are complete.
If these properties cannot be proved for every required path, stop and request
architecture review; do not reduce the approved scope or substitute a
classical-only authentication profile.
