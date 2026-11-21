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

For a node serving mixed channels, the conservative shared-listener candidate
requires the strictest applicable policy for every connection on that
listener. This would also reject classical clients of weaker channels on the
same listener; it must not change behavior on nodes where PQ4 is not selected.
Separate strict and classical listeners could retain mixed connectivity, but
would additionally require non-bypassable binding of every request and
stream to its listener's permitted channels. This is not a single generic
pre-handshake check: for example, the
[endorser](../../core/endorser/endorser.go) extracts the channel from a
proposal, [delivery](../../common/deliver/deliver.go) reads it from an
envelope, and [gossip](../../gossip/comm/comm_impl.go) has a bidirectional
stream with its own message handling. Neither candidate has been proved in a
Fabric network or selected by the architecture review.

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

An authentic signature alone does not establish policy freshness: an older,
validly signed policy remains valid. If an attacker can restore every piece
of node state to an earlier snapshot, the restarted node cannot distinguish
that snapshot from its original execution without a trusted freshness source
outside the restored state. The review must identify such a source or
explicitly exclude that attacker. Likewise, software enforcement cannot
protect a node whose attacker can replace its binary or control its process;
these boundaries must not be hidden behind a signed-policy claim.

## Feasibility evidence and gaps

The [component tests](validation-and-evidence.md) demonstrate native
hybrid/ML-DSA handshakes and cause-specific TLS rejections in controlled
configurations, plus ML-DSA compatibility with Fabric comm, MSP TLS roots,
Raft certificate metadata, administration HTTP components, and the Fabric
CCAAS client components with a TLS-enabled shim. They also show that the
current Fabric comm, admin and shim servers accept classical-only key
exchange. The test-only additional certificate check does not authenticate
a network policy or enforce it in Fabric.

Baseline and pinned-upstream peer and orderer processes also rejected a
genesis containing a deliberately unknown test capability with an explicit
unsupported-capability diagnostic. That is evidence about unknown-capability
handling only: no PQ4 capability exists, and the test does not establish
pre-handshake protection or prevent classical connections.

An isolated [test-only policy prototype](../../integration/pq4/feasibility/policy_prototype_test.go)
also verifies an ML-DSA-65-signed policy and a separately supplied trusted
checkpoint before producing a server TLS configuration. It binds a sample
channel-config protobuf hash to the policy; Fabric's `channelconfig.NewBundle`
parses that sample. The prototype rejects missing, tampered, stale,
conflicting and weakened inputs. Its strict listener configuration rejects
TLS 1.2, X25519-only key exchange and an ECDSA client certificate.
This tests the strongest-policy-before-handshake idea without selecting it
as the architecture. If both the older policy and its checkpoint are
restored, the prototype accepts them: the checkpoint must actually be
protected against rollback.

The prototype has no real durable or external checkpoint, provisioning or
rotation mechanism, Fabric channel-update authentication, RPC/channel
authorization, independent client-side policy, peer/orderer listener
integration, CCAAS or admin enforcement, or transaction binding. Its exact
config-hash pinning also requires a separate authenticated policy/checkpoint
update whenever a channel configuration changes. Neither an in-memory
checkpoint nor a sample channel proves the corresponding production properties.

A [live baseline experiment](validation-and-evidence.md#live-baseline-configuration-and-rollback-experiment)
also distinguishes stale updates from storage rollback: Fabric rejected an
unauthorized config update and a stale signed replay, but permitted an
authorized removal of a redundant, unprotected capability. Restoring the
single orderer's earlier ledger and Raft state after shutdown caused it to
serve the previous configuration and accept the previously stale update on
restart. The two peers were stopped before the restore; this does not
prove any PQ4 transport policy.

A separate baseline three-orderer Raft experiment kept an unrolled-back
quorum running, advanced all orderers' configuration, and restored one
orderer's earlier ledger and Raft state. In three runs the restored orderer
panicked because its Raft commit index exceeded its restored log index.
The experiment is not a PQ4 policy and does not establish that the orderer
refuses old policy before catching up, that a node validates freshness before
accepting TLS connections, or that a restored quorum or a separate
CCAAS/admin endpoint is protected.

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

No positive or negative PQ4 policy-integration test, PQ4-required
unsupported-binary test, or network-wide PQ4 transaction has been run. A
design assertion or the standalone TLS success does not satisfy those tests.
The additional Go
`VerifyConnection` feasibility experiment rejects classical leaf keys only
after normal chain validation; it does not address authenticated policy,
root/chain profile requirements or the selection of an implementation.

## Review and stop

Do not begin PQ4.1 or claim network-wide post-quantum transport until the
remaining enforcement feasibility work and architecture review are complete.
If these properties cannot be proved for every required path, stop and request
architecture review; do not reduce the approved scope or substitute a
classical-only authentication profile.
