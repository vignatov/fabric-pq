# PQ4.0 transport-policy enforcement review

Managed protected peers and Raft orderers authenticate enrollment before
starting channel services. Their shared and administrative listeners use the
authenticated transport floor. Direct unmanaged startup serves baseline
deployments. Production verification and bounded endpoint coverage are
tracked in [PQ4.0E status](pq4.0e-status.md). PQ4.0E.1 separately verifies
Fabric history before a trusted provisioner issues non-genesis join approval;
this does not certify network-wide transport enforcement or close PQ4.0B.

Status: **enforcement NOT PROVEN; PQ4.1 is blocked**. PQ4.0D adds the local
orderer configuration authorization boundary. Strict service endpoint and
shared-listener enforcement still require integration evidence.

### Isolated managed orderer provisioning

Use the signed launcher and service-manager contract described in the
[PQ4.0E provisioning guide](pq4.0e-status.md). Provision a private local
Linux state directory and protect its ancestors before startup. The pinned
policy signer contains raw ML-DSA-65 public key bytes. The state directory
uses the PQ4.0C `checkpoint` record produced by `Store.Provision`. Supply
`Version` as the initial node checkpoint version, `Digest` as the 32-byte
SHA-256 array of the signed policy payload, and `Policy` as an object with
the base64 fields `Payload` and `Signature`.

Supply
`genesis-<sha256(channel-id)>` as a JSON string containing the lowercase
hex Fabric genesis header hash. For later-block participation joins, also
supply `genesis-<sha256(channel-id)>.block` with the raw Fabric block and
the independently signed join target described in the provisioning guide.

Stage each operator authorization as a complete JSON record named
`approval-<sha256(channel-id)>-<next-node-checkpoint-version>`. Its four
base64 fields are `Transition`, `TransitionSignature`, `Policy` and
`PolicySignature`. Publish the file atomically before submitting the
configuration. The node-wide checkpoint serializes operator transitions.
The initial policy must bind every protected channel this node serves.

The revised PQ4.0 baseline uses trusted operator-protected local state. It
requires the strict profile for every connection on a shared listener that
serves at least one PQ4-required channel. The independent witness is research
evidence, not a mandatory runtime dependency. Complete host-state rollback
remains outside the development threat model and must not be claimed as
detected.

## PQ4.0B selected local authorization

`PactwayPQTransportV1` is the selected channel-level transport capability,
separate from the existing hybrid enrollment capability. It specifies
`pactway-pq-tls-v1`, is permitted only at fresh genesis, and cannot be removed
from a protected channel. Its presence does not replace the authenticated
local bootstrap policy or protect pre-channel handshakes.
The profile's endpoint-authentication check requires an ML-DSA-65 leaf key;
the X.509 path and hostname are still verified normally. It does not require
ML-DSA CA/intermediate keys or certificate signatures, so a trust path may
include classical cryptography and is not claimed to be quantum resistant.

The operator provisions a dedicated policy-signing trust anchor, separate from
TLS and enrollment keys, and protected local policy and checkpoint state. The
signed policy binds network and node identity, the mandatory transport floor
and a monotonically increasing checkpoint version and digest. A new channel
configuration requires both normal Fabric authorization and a separate signed
local transition identifying the network, node, channel, previous checkpoint
version and digest, new configuration sequence and digest, new checkpoint
version, and mandatory transport floor.

The intended procedure durably prepares that authorization before activation,
validates the Fabric-authorized configuration against it, then atomically
commits the local policy and checkpoint after successful validation. Restart
must reconcile prepared and committed state without accepting an unauthorized
configuration, and any mismatch must fail closed for the channel. Merely
observing a new configuration never authorizes or advances a checkpoint.
Replayed, skipped, conflicting, unauthorized and weakened transitions must
fail. No external freshness service is required under this development model.

Fabric lifecycle ordering remains a proof obligation: peer configuration
application occurs during block validation, and the orderer updates its bundle
before its config block is durably written. Both paths can expose a new bundle
before the corresponding post-commit hook. A safe activation and recovery
barrier must be demonstrated without ledger divergence or silently serving an
unauthorized channel. If that requires a fundamental expansion of the focused
prototype, stop for architecture review rather than declaring the gate passed.
The [configuration activation ADR](adr-config-activation.md) identifies
candidate interception and recovery points for review; it is not an approved
implementation design.

The focused PQ4.0B components authenticate policy and verify signed transition
values. The bounded PQ4.0E integration adds managed startup, native Fabric
validation and journaled publication. Deployment enforcement and network-wide
transport require separate evidence. [PQ4.0B gate report](pq4.0b-gate-report.md)

## Candidates

| Candidate | Strength | Unresolved security gap |
| --- | --- | --- |
| Authenticated channel capability alone | Authenticated version and unsupported-binary rejection can be tied to channel configuration. | The TLS handshake occurs before a channel is identified or its configuration can be read; admin and CCAAS may have no channel context. This candidate alone cannot establish the required pre-handshake protection. |
| Trusted, versioned node/network transport policy alone | Can govern bootstrap, all listener and client construction, CCAAS and admin before a channel is known. | Needs an authenticated trust anchor, provisioning and rollback protection, agreement with network/channel requirements, and a way to prevent old binaries from silently participating. A local environment flag by itself is insufficient. |
| Layered node policy and authenticated channel requirement | Proposed development design can bind a pre-handshake minimum to a channel's authenticated requirement and cover non-channel paths. | The binding, bootstrap trust, downgrade-resistant updates and old-binary behavior remain unimplemented and unproved. Architecture approval remains pending. |

Do not treat the existing `PactwayHybridCertificatePactwayV1` enrollment
capability as a transport capability. If a distinct transport capability is
chosen, its precise semantics, fresh-genesis behavior and removal protection
must be implemented and tested; a capability by itself does not control TLS.

The development baseline instead relies on a trusted operator-protected local
checkpoint, bootstrap policy and trust anchors. It does not detect simultaneous
restoration of all local state. An independently protected freshness authority
or hardware-backed checkpoint is optional research for a stronger production
threat model; it is not a PQ4.0 development prerequisite. Such a source would
need a trust domain outside restored node snapshots, authenticated access and
updates, rollback-resistant storage, and recovery procedures. None of those
properties has been implemented or verified by the local witness experiment.

For a shared listener serving any PQ4-required channel, the selected rule
requires strict PQ4 policy for every connection; reject the mixed
configuration if that cannot be guaranteed. This also rejects classical
clients of weaker channels on that listener, but must not change behavior
where PQ4 is not selected. Separate strict and classical listeners are not
part of the initial demonstration. If considered later, they would require
non-bypassable binding of every request and stream to its listener's permitted
channels. This is not a single generic pre-handshake check: for example, the
[endorser](../../core/endorser/endorser.go) extracts the channel from a
proposal, [delivery](../../common/deliver/deliver.go) reads it from an
envelope, and [gossip](../../gossip/comm/comm_impl.go) has a bidirectional
stream with its own message handling. Strongest-policy enforcement has not
yet been proved in a Fabric network.

## Trust boundaries and required design decisions

- Define who provisions and authenticates a bootstrap policy, its trust
  anchors, network identity, version and anti-rollback state; specify what
  happens before a peer joins and before the orderer receives its genesis.
- Bind authenticated channel requirements to that policy and fail closed on
  missing, stale or conflicting state. Specify the attacker and the
  consequences of an administrator or host with access to local keys,
  configuration, binaries or persistent rollback state.
- Implement the selected strongest-policy rule and prove that a weaker
  channel cannot create a path into a PQ4-required channel.
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
outside the restored state. The development threat model explicitly excludes
that attacker; a stronger production threat model must identify such a
source. Likewise, software enforcement cannot protect a node whose attacker
can replace its binary or control its process;
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

Another component test supplies release-directory `connection.json` to the
actual external-builder reader and external-chaincode runtime. Both
`tls_required: false` alone and that setting combined with
`client_auth_required: true` result in a plaintext registration stream to a
test gRPC server, with no server-observed client authentication. The test
does not run a Fabric peer or prove that an attacker can alter an installed
package. It does show that a future strict policy cannot treat the metadata's
client-auth flag as evidence that TLS was enabled. A separate test-only guard
rejects plaintext metadata but does not validate client authentication,
ML-DSA identity or hybrid key exchange. Actual strict CCAAS enforcement must
validate those properties at the peer and server enforcement points.

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
This tests the strongest-policy-before-handshake idea without integrating it
into a Fabric listener. If both the older policy and its checkpoint are
restored, the prototype accepts them: the checkpoint must actually be
protected against rollback.

The prototype has no real durable or external checkpoint, provisioning or
rotation mechanism, Fabric channel-update authentication, RPC/channel
authorization, independent client-side policy, peer/orderer listener
integration, CCAAS or admin enforcement, or transaction binding. Its exact
config-hash pinning also requires a separate authenticated policy/checkpoint
update whenever a channel configuration changes. Neither an in-memory
checkpoint nor a sample channel proves the corresponding production properties.

The prototype also retrieves a policy from a separate test directory over a
local HTTPS server and uses its version and digest as the assumed checkpoint.
With a current witness, restoring an older signed node policy is rejected;
with the witness restored too, that older policy is accepted. The test verifies
TLS 1.3, the hybrid group, ML-DSA mutual credentials, rejection of an untrusted
server and a missing client certificate. After the server is stopped, the
test explicitly supplies no checkpoint and bootstrap fails. The directories
and server share the test process and host: this does not demonstrate
independent protection, durable monotonic storage, trusted authority updates,
automatic fail-closed behavior, or any production bootstrap integration.

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

## Revised PQ4.0 gate

The following focused prototype evidence is required before PQ4.1:

1. A strict listener rejects TLS 1.2 and classical-only X25519 key exchange.
2. A strict listener rejects classical-only endpoint authentication.
3. An approved ML-DSA mutual-TLS handshake succeeds with X25519MLKEM768.
4. Bootstrap verifies policy and trust anchor before listener readiness.
5. Missing, invalid or conflicting bootstrap configuration fails closed.
6. A versioned authenticated channel capability agrees with local policy.
7. Unauthorized channel downgrade or removal is rejected.
8. An unsupported binary rejects the PQ4 capability.
9. Strict CCAAS rejects `tls_required=false`, even when client authentication
   is requested.
10. Strict administration transport rejects weaker TLS and authentication.
11. The prototype explicitly records that complete host-state rollback cannot
    be detected in the isolated development threat model.

For shared listeners, the initial implementation must enforce the strict
profile for all connections on any listener serving a PQ4-required channel.
Where that guarantee cannot be implemented, mixed configuration must be
rejected. Later listener separation must prove channel-to-listener binding
and must not provide a bypass around the strict policy.

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
