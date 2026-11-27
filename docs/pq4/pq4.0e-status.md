# PQ4.0E bootstrap and admission: INCOMPLETE

This development checkpoint covers authenticated enrollment and bounded
admission on native peers and Raft orderers. The bounded PQ4.0E.1
implementation at `0c3e9db3402dbc87d536d0959442266f4c75c256` passed hosted
CI and independent review for merge, subject to DCO sign-off. PQ4.0E.3 adds
a controlled Linux provisioning demonstration. Its final-head hosted CI passed,
and the independent security review supported the bounded implementation.
PQ4.0E development acceptance remains incomplete pending explicit independent
sign-off on the reconciled evidence and trust boundary. Production deployment
certification is a separate assessment. The PQ4.0B network enforcement gate
remains incomplete. [PQ4.0E.3 development gate report](pq4.0e3-development-gate.md)

## Current boundary

When any orderer `General.PQActivation` field is configured, the registrar
opens the configured activation store, authenticates the policy embedded in
its checkpoint against the configured signer and node/network identity, and
derives channel membership from that policy. The ordinary channel list cannot
remove a binding; a listed channel absent from the policy is an error. The
registry rejects corrupt journals and durable channel records that no longer
correspond to a policy binding. Channel recovery, replay readiness and
quarantine remain separate requirements.

An orderer configured for protected activation without a verified managed
handoff rejects startup before listener initialization. A managed process
gets its startup security floor from verified enrollment. Unmanaged startup
with activation settings absent follows the legacy path.

The Linux launcher verifies signed enrollment and history and rejects invalid
protected startup evidence. The trusted VM provisioner and service manager
must control authorized launches. The direct Fabric binary still supports
legacy unmanaged startup with activation settings absent.
The hosted VM test exercises the fixed systemd unit with a native orderer and
test enrollment. Production VM provisioning and network exposure require
deployment-specific verification.

## Managed launcher contract

`pq-launcher` receives absolute, clean paths to a provisioning-authority
ML-DSA-65 public key, a signed manifest, and signed history. Each signed file
is canonical JSON `{ "payload": ..., "signature": ... }` without whitespace;
the byte arrays are base64 encoded as in Go JSON. The payload is canonical Go
JSON of the corresponding enrollment structure. The signature covers the
domain `fabric-pq/enrollment/v1` or `fabric-pq/enrollment-history/v1`, a NUL
byte, and the exact payload bytes. History binds the manifest payload digest,
identity and provisioning generation. It records `protected_ever`, and a
baseline manifest is rejected if that value is true.

The VM provisioner must install the launcher, Fabric executable, service unit,
authority key, manifest and history in root-owned locations whose files and
parent directories are not writable or removable by the service account.
Managed service configuration must invoke only the launcher with those paths;
the provisioner must not configure a direct Fabric service or allow ordinary
configuration to replace the service unit. The history must be updated by the
trusted provisioner before a new manifest becomes active, preserving
`protected_ever`; an interrupted update must fail closed. The launcher rejects
provisioning evidence inside the resolved runtime state or ledger directories.
The disposable VM test verifies the repository installer and service unit.
Production provisioning and control of authorized launches remain pending.

The repository includes `sampleconfig/fabric-pq-managed.service` for the
managed service. It fixes the launcher and evidence paths in the root-owned
unit, uses a dedicated `fabric-pq` account and makes the operating system
read-only to that account except for `/var/lib/fabric-pq`. A trusted operator
must provision that account, binaries, evidence and configuration, prevent
competing direct Fabric services, and verify mount and service-manager policy.
`scripts/install-pq-managed-service.sh` installs the unit and launcher from
root-owned trusted source paths, checks the provisioning files and ancestors
for unsafe ownership, permissions and extended ACLs, refuses existing unit
drop-ins, and does not enable or start the service. It requires `getfacl` and
must be run as root on the VM. The unit and installer are deployment artifacts;
placing it in this repository does not install or enforce it on a VM.

The development threat model trusts the host kernel, service manager and
privileged provisioner. It allows node configuration errors and interruption
during provisioning. Arbitrary process execution under the service account is
outside the current proof. A deployment that includes that threat needs OS
controls that prevent the account from launching an alternate peer or orderer
against the same ledger and credentials, and a test of those controls.

For protected mode, the launcher verifies the pinned policy signer and
authenticates the active checkpoint before executing the signed `peer node
start` or `orderer start` command. The node independently verifies the
handoff, executable, arguments and ledger directory. Peer channel creation
and the orderer registrar select protected channels from that registry.
For a valid baseline declaration the launcher executes the signed command
without a protected handoff. Linux is the supported managed platform.

## Remaining work and evidence

| Property | Status |
| --- | --- |
| Registry derives membership from authenticated checkpoint | Native managed peer and orderer select enrolled channels from the signed policy and checkpoint |
| Reject unmanaged protected configuration before serving | Unmanaged protected orderer config rejects startup; managed nodes authenticate before listener setup |
| Signed manifest, protected history and Linux launcher | Linux race and subprocess tests passed; managed deployment incomplete |
| Fixed managed systemd unit and installer | Disposable systemd VM test installs and inspects the real unit |
| Non-bypassable managed VM deployment and protected-to-baseline prohibition | Disposable VM test covers the trusted service-manager boundary; production validation pending |
| Authenticated onboarding and non-genesis join provenance | PQ4.0E.1 replays complete history before issuance. PQ4.0E.2 adds provisioner-pinned exporter evidence, complete pre-signing inventory verification, private staging and a versioned peer snapshot anchor. PQ4.0E.3 adds signed pre-export authorization and a Ledger A/B process/filesystem test. The [PQ4.0E.3 gate report](pq4.0e3-development-gate.md) records the final-head hosted evidence and implementation review. Independent development acceptance remains pending. |
| Peer bootstrap and endorsement, Gateway and background admission | Managed peer startup installs the verified channel registry and strict shared listener |
| Peer native commit adapter with staged approval | Real-ledger race tests passed; protected channel creation installs the adapter |
| Protected peer lifecycle assembly | Protected channel creation recovers private validation, serving publication and guarded commits before exposing the channel |
| Orderer service, stream and follower integration under strict transport | Native Broadcast, Deliver, participation update and separately tested authenticated follower promotion |
| Orderer broadcast validation generation lease | Broadcast holds the validated generation through cancellable readiness and submission |
| Cluster send cancellation and shutdown reporting | Forwarding retains the exact submit generation through the stream handoff |
| Orderer Raft generation lease | Local submission transfers admission through the pending batch and proposal queue to the Raft proposal call |
| Protected Raft membership retry | Implemented; focused race and repeated promotion tests passed |
| Staged shared TLS resources and crash/restart reconstruction | Mixed-peer real-ledger and strict gRPC proof, with focused orderer multi-listener staging tests |
| Peer credential roots preparation and publication failure | Fallible cache retirement precedes TLS and endpoint installation while protected admission is closed |
| Gateway cache publication and admission | Protected unary admission, strict routed transport and revocable event streams wired |
| Orderer protected bundle callbacks | Managed orderer stages listener and cluster dialer trust before publishing either |
| Runtime service coverage | Recorded below, including endpoints disabled for enrolled channels and network-wide enforcement gaps |
| Managed operations listener and profiling | Authenticated strict mTLS for operations; managed startup rejects an enabled profiling listener |
| Full regression, integration and final-head CI evidence | The [PQ4.0E.2 acceptance report](pq4.0e2-acceptance.md) and [PQ4.0E.3 gate report](pq4.0e3-development-gate.md) record results for their respective revisions. PR #15 final-head Verify Build and PQ3 passed. The PQ4.0E development decision and PQ4.0B gate remain incomplete. |

Complete privileged-host replacement or rollback of all protected
provisioning state remains outside the development threat model.

### PQ4.0E.1 provenance verifier implementation

The `internal/pkg/pqtransport/provenance` helper replays a complete,
consecutive block history from the genesis block anchored by the authenticated
protected registry to the exact requested configuration-block boundary. It
uses Fabric's native block-verification assistant for block signatures under
the historical `BlockValidation` policy, header continuity and data hashes;
Fabric's configuration validator for each transition under the preceding
configuration; and native bundle compatibility checks. It also checks
channel identity in every envelope, both representations of `LAST_CONFIG`,
configuration sequence progression, and the channel's Raft consensus
metadata. The target's deterministic configuration digest, channel, network,
node and `pactway-pq-tls-v1` binding must match the authenticated local policy
and checkpoint.

The `internal/pkg/pqtransport/provisioning` helper ties replay to the registry's
protected genesis record and exposes orderer and peer-snapshot anchor signing
functions that accept only a successful verification result and the matching
policy signer. Its deterministic report identifies the verified source
history, genesis, target, configuration, historical verification policies,
transport profile and exact join-anchor digest. Rejected verification can
return a report with an explicit failure reason. The signer private key remains
an external provisioning responsibility and is not part of node state.

Offline verification does not establish live Raft quorum or voter readiness;
the existing participation-follower promotion and snapshot paths must continue
to perform their native checks. Only Raft consensus is supported; other
consensus types and consensus-type transitions fail closed. The supported peer
snapshot boundary remains a configuration block. Snapshot state provenance
requires an independently trusted exporter and provisioner verification of
payload hashes; replay and import-time integrity checks do not prove it.

Focused history tests use Fabric-generated configuration updates and actual
Fabric MSP signatures. They cover complete history, invalid signatures,
valid signatures presented under an unauthorized MSP identity, broken links,
missing blocks, unauthorized configuration updates, wrong genesis/channel,
checkpoint mismatch, unsupported consensus and snapshot boundaries, and
registry-bound anchor signing.
Linux race integration tests also exercise registry-bound anchor issuance
through native managed orderer promotion and peer snapshot import/recovery.
The protected-registry genesis-binding test is Linux-only because the
activation store requires directory syncing. Local disposable Linux race
tests and `go vet` passed locally. On final reviewed commit
`0c3e9db3402dbc87d536d0959442266f4c75c256`, the hosted Verify Build, including
all unit tests, nine integration groups, Basic Checks, focused PQ4.0E.1 tests
and the PQ4.0E disposable-VM proof, passed. PQ3 isolated acceptance also
passed. The first PR unit-test attempt failed in an unchanged Gateway timeout
test; its same-head rerun passed, as did the push-triggered unit run. The
bounded implementation review accepted this commit for merge subject to DCO
sign-off. These results do not complete the PQ4.0E development gate; remaining
acceptance evidence, independent snapshot-state provenance and production
qualification are still outstanding.

### PQ4.0E.2 trusted snapshot export

The `provisioning.SignVerifiedPeerSnapshotAnchor` entry point no longer
accepts arbitrary metadata bytes. It requires the opaque result of
`VerifySnapshotExport`, which verifies an exporter signature using a
provisioner-pinned ML-DSA-65 key and checks the independently configured
exporter and source-ledger identities against that pin, while matching the
history boundary to the registry-bound `VerifiedJoinHistory`. Versioned
evidence binds the source-history identity, genesis and configuration
boundary, exact native metadata byte hashes and complete payload inventory.
The exporter identity, public-key pin, and
expected source-ledger identity must come from the trusted provisioning
boundary, not from snapshot files.

`VerifySnapshotExport` rejects missing or unexpected entries, unsafe names,
symlinks, non-regular files, altered hashes and inconsistent metadata. It
copies the authenticated files and evidence into a private, read-only staging
directory; the signer rechecks that staged content immediately before issuing
the anchor. The peer anchor uses the explicit
`fabric-pq/peer-snapshot/v2` domain and format and binds the evidence digest,
exporter identity, source-ledger identity and approved exporter public key.
There is no v1 fallback: old peer snapshot anchors fail closed and require a
new trusted approval for separately provisioned onboarding. No in-place
migration of an existing v1 snapshot-backed ledger is currently supported;
see the [upgrade boundary](pq4.0e2-snapshot-provenance.md).

The importer verifies the exporter evidence and exact native metadata before
copying only the listed payloads into its private native-import directory. It
retains the evidence beside protected state and requires it again during
restart recovery. Missing evidence cannot reopen the protected channel.
Managed protected snapshot-export RPC restrictions remain unchanged; this
workflow uses a separate offline or isolated source-export boundary.

The source exporter, its ledger, the trusted provisioner and operator, and the
isolated host filesystem are trusted. A compromised trusted exporter can sign
false state, which file hashes cannot detect. This is not a cryptographic
commitment from Fabric block history to arbitrary world state. The
PQ4.0E.2 APIs still do not attest a physical source-ledger directory;
PQ4.0E.3 demonstrates that association through signed pre-export authorization,
restricted path access, and controlled native ledger opening. The complete
security boundary and limitations are documented in the
[PQ4.0E.3 provisioning guide](pq4.0e3-provisioning.md).

The focused Linux race-enabled native test covers approved export, a
self-consistent recomputed-hash substitution without fresh exporter approval,
metadata and payload tampering, unsafe package entries, operator-key mismatch,
protected import, restart with evidence, and restart without evidence. The
PQ4.0E.3 disposable-VM test additionally covers source-path substitution,
unapproved Ledger B access, independent exporter authorization, evidence
replacement after staging, v2 approval, peer restart recovery, and baseline
ledger continuity. Final-head hosted CI and independent review remain required.

Local validation was run on Linux/amd64 with Go 1.27.4, `GOFIPS140=off`, in a
disposable `golang:1.27.4` container. All commands below passed:

```text
go test -mod=vendor -race -count=1 -v ./internal/pkg/pqtransport/provenance ./internal/pkg/pqtransport/provisioning ./internal/pkg/pqtransport/enrollment
go test -mod=vendor -race -count=1 ./internal/pkg/pqtransport ./internal/pkg/pqtransport/activation/...
go test -mod=vendor -race -count=1 -run '^TestPQ40EManagedOrdererNonGenesisPromotion$' ./orderer/common/multichannel
go test -mod=vendor -race -count=1 -run '^TestPQ40ESignedNonGenesisSnapshotJoinAndRecovery$' ./core/peer
go test -mod=vendor -race -count=1 ./orderer/consensus/etcdraft
go vet -mod=vendor ./internal/pkg/pqtransport/... ./orderer/consensus/etcdraft ./core/peer
```

Operator usage and evidence format are documented in
[PQ4.0E.1 Fabric provenance verification](pq4.0e1-provenance.md); current and
historical hosted results are distinguished in the
[PQ4.0E.2 acceptance report](pq4.0e2-acceptance.md).

### Service and publication inventory

| Runtime path | Admission and publication boundary | Evidence or open dependency |
| --- | --- | --- |
| Peer ledger load and CSCC join | The authenticated registry selects protected channels. Existing runtime checks the signed target anchor and snapshot metadata before ledger creation; PQ4.0E.1 adds full-history verification at trusted provisioning before anchor issuance. The controller restores the private validation bundle and serving resources before publication. | Native genesis join/restart and real-ledger signed non-genesis snapshot issuance/import/recovery passed local Linux race tests and the PQ4.0E.2 hosted job; exact revisions and current-head evidence are tracked in the [acceptance report](pq4.0e2-acceptance.md). Other snapshot targets require additional signed state-transfer evidence. |
| Peer endorsement, CSCC config reads and QSCC ledger reads | Endorsement retains the serving generation through unary gRPC completion. CSCC and QSCC acquire the target channel separately when the query names a channel outside the proposal header. Node-local channel and join-status listing use local ACLs. | Native protected queries before and after restart, and refusal with persisted quarantine. Component test for blocked unary response serialization. |
| Peer block, filtered and private-data Deliver | All three RPCs share the protected seek admission and retain it through iteration, ACL checks and sends. Revocation closes a waiting iterator or aborts a blocked send. | Mixed-channel best-effort Deliver with protected cancellation, continued baseline streaming, and protected recovery. Existing filtered and private-data response tests exercise the data formats. |
| Peer Gateway | Evaluate, Endorse, Submit, CommitStatus and ChaincodeEvents use the protected generation. Ordered cache retirement precedes installation of staged endpoints and roots. Routed protected calls use the strict client policy. | Registry and RPC tests cover failure, cache reconstruction, unary completion and event-stream drain. Network-wide external Gateway topology is deferred. |
| Peer discovery | Per-channel queries acquire separate leases through the unary response. Local membership is node-scoped and uses its local policy. | Strict gRPC mixed-query test across failure and restart. |
| Peer gossip, block delivery and private data | Shared listener and managed outbound clients use the strict profile. Protected block commit, state-transfer replies, private-data storage, pulls and distribution honor channel admission. An in-flight protected reply can force reconnect. | Mixed real-ledger commit and TLS restart proof, plus focused queue and private-data tests. End-to-end authenticated gossip topology across independently managed nodes is deferred. |
| Peer chaincode registration, execution and CCAAS | Strict registration with a local ML-DSA-65 CA, and strict authenticated external connection setup for managed peers. Protected invocation takes admission before lifecycle lookup. Cross-channel calls retain target admission through the source shim response. | Focused lease, queued and in-flight revocation, restart and live external connection-abort tests. A complete deployed CCAAS topology is deferred. |
| Peer snapshot export | Generate, Cancel and QueryPendings still reject enrolled channels. PQ4.0E.2 approval uses a separately authorized offline/isolated exporter; the importer stages only authenticated content and retains export evidence for recovery. | Native signed protected Generate rejection remains. Focused native export/import and negative substitution tests pass; no remote export bypass was introduced. |
| Orderer Broadcast and Raft | The validated generation survives readiness, forwarding, batching and the Raft proposal call. Native replay and quarantine gate user traffic. | Native mixed Broadcast/Deliver restart and controlled proposal-queue tests. |
| Orderer AtomicBroadcast Deliver | Both normal and best-effort seeks hold admission through iteration, ACLs and block sends. In-flight revocation can force reconnect on the affected transport. | Native best-effort stream cancellation, baseline continuity and restart. |
| Orderer cluster and follower | Shared or configured dedicated cluster transports use the strict profile. Application submission carries the generation. Authenticated Raft replication and follower verification can proceed for recovery while application admission is closed. | Strict authenticated Cluster Step and Raft Submit tests, native replay/quarantine and signed non-genesis follower promotion. Managed protected channels require Raft. Full SmartBFT protection is deferred. |
| Orderer participation admin | Strict mTLS on all routes. Join verifies signed provenance. Update validates and submits in one generation. List and status report node metadata. Protected HTTP block export and channel deletion are disabled. | Native strict admin update, protected export and deletion rejection, baseline block export and restart. Protected block retrieval is available via Deliver. Protected deletion requires the decommissioning process below. |
| Shared TLS and configuration callbacks | Peer validates roots and retires caches before publishing roots/endpoints. Orderer prepares every affected listener pool and cluster dialer trust before installing either. Fabric MSP, bundle and gossip state publish through the activation callback. | Mixed native ledger and strict listener proof, including unrelated baseline traffic and recovery after failure. Orderer trust-pool failure coverage is focused. |
| Node-wide operations, health, profiling | Operations HTTP health, metrics, log specification and version use mandatory strict mTLS on managed nodes. gRPC health uses the configured server transport. Managed startup rejects the separate profiling listener. | Native listener tests and disposable VM orderer socket inventory. Production routing, firewalls and actual listener exposure remain pending. |

Normal channel configuration and participation deletion cannot decommission
a protected enrollment. An authorized provisioner must retire the managed
service and its credentials, archive or securely dispose of the ledger under
the deployment's retention policy, and preserve the signed enrollment history.
A replacement with different protection requirements must use separate trusted
provisioning and separate ledger state. This phase supplies no automated
decommissioning operation.

## Authenticated non-genesis onboarding

The policy signer pinned by the managed manifest signs a canonical
enrollment envelope for each channel's join target. The envelope contains the
network, node, strict transport profile, channel ID, genesis header hash,
target block number and header hash, and configuration sequence and digest.
The configuration digest is SHA-256 over deterministic protobuf bytes.
Provision `genesis-<sha256(channel-id)>` and its `.block` file as for a
genesis join. The join envelope independently binds the same genesis hash.

For an orderer, provision `join-orderer-<sha256(channel-id)>` under the
activation state directory. Sign the payload with domain
`fabric-pq/orderer-join/v1` and a NUL separator. The registrar verifies the
anchor before creating the ledger or trusting a pending join block on
restart. The follower pulls from the signed genesis and verifies Fabric
history and staged operator approvals before promotion. A recovered ledger
that already reached the target must contain the anchored block header.
The orderer still reconciles native Raft replay before opening admission.

For a peer, provision `join-peer-<sha256(channel-id)>` and its `.block`
file containing the target configuration block, plus the authenticated
`_pactway_snapshot_export_evidence.json` sidecar and native snapshot files.
The operator signs the versioned `fabric-pq/peer-snapshot/v2` anchor, which
binds both native metadata byte hashes, the export-evidence digest, exporter
identity, source-ledger identity and exporter public key. The provisioner
must verify the exporter against its independent pin and verify every file
before signing. The peer authenticates the sidecar, copies only the enumerated
files into a private directory, and retains the sidecar in protected state.
Snapshot height and hash must match the target configuration block. Restart
re-authenticates the retained evidence, metadata and anchor and checks ledger
linkage before admission can open. Older v1 peer snapshot anchors are not
accepted as a fallback.

The bounded snapshot path covers a snapshot taken at a configuration block.
Snapshot targets between configuration blocks require an additional signed
state-transfer contract and remain unsupported.

## Disposable VM test

The hosted Ubuntu test installs the repository systemd unit, real launcher
and native orderer on a fresh VM. It checks ownership, all trusted path
ancestors, ACLs, the systemd service account and mount permissions. It verifies
loopback strict mTLS operations and participation admin, then checks that
deleted enrollment, mismatched history, a signed baseline declaration after
protected enrollment and insecure operations configuration all fail closed.
It also tests whether the service account can register a competing system
unit. This runs only on an explicitly opted-in disposable VM.
The test inventories live TCP sockets owned by the running orderer and
compares them with the expected loopback bindings for the shared gRPC,
operations and participation listeners before and after restart.

Production evidence requires an authoritative node and listener inventory.
For each deployed peer and orderer, identify the environment and version,
verify the active system-manager unit, trusted file ownership and mounts,
and record binary digests and signed enrollment status. Compare the actual
listeners, bind addresses and TLS requirements with approved access from
each client, cluster, operations and admin network. Include effective cloud
and host firewall rules, routing and load balancers. Verify peer chaincode
listeners separately and confirm that standalone profiling is disabled.
Use a read-only inspection path. The disposable test's loopback topology
does not establish the exposure of a production deployment.

## Mixed-channel recovery tests

The managed orderer subprocess test serves a protected channel and a
baseline channel over one strict listener. It exercises an authorized
protected transition, verifies that a previous-generation protected
Deliver stream closes, and commits a baseline update through the existing
baseline stream. Both ledgers remain available after native restart.

The mixed peer test uses real ledgers, gossip block delivery, the protected
activation controller and a live gRPC listener with client authentication.
An injected cache retirement error after a protected configuration commit
keeps candidate roots and cache contents private. The peer stops that
channel's gossip block processing, keeps its admission closed and continues
committing on the baseline channel. Restart reconstructs both ledgers and
publishes the committed roots. A separate Gateway registry test rebuilds
orderer endpoints from the recovered bundle while discovery advertises a
stale endpoint.

The mixed peer test also sends one authenticated discovery RPC with queries
for both channels. A closed protected generation yields an error for its
query while the baseline query succeeds. After restart both queries succeed.
The discovery service keeps the generation lease through its unary response.
The same peer test exercises private-data distribution and transient-store
admission before failure, while the protected channel is closed, and after
restart.

Inbound private-data storage, private-data pulls and state-transfer replies
also require the serving generation on protected channels. The gossip
transport discards queued replies from closed generations. If revocation
interrupts a blocked write, it closes the affected transport and waits for
the writer to return. Other traffic on that connection reconnects. The
transport tests cover both queued cancellation and in-flight drain.

Chaincode execution acquires admission before resolving and launching the
chaincode. The mixed-channel test exercises an outstanding invocation
during closure, continued baseline execution, and a rebuilt handler after
recovery. Cross-channel calls acquire target admission before checking its
ACL or opening its ledger simulator and retain it through the asynchronous
source-shim send. Revocation discards queued payloads and sends a generic
error. If a write has started, revocation closes the shim connection and
drains the writer before releasing admission. Calls sharing a disconnected
shim require a fresh connection. The test reopens the signed checkpoint and
verifies that a new shim receives protected responses again.

The cluster test uses authenticated strict mTLS, the real Cluster Step
service, member-certificate mapping and the Raft Submit entry point. It
checks cancellation at the protected submission queue, rejection while
closed, independent baseline traffic, and a fresh transport/controller
after reopening the checkpoint. Native Raft persistence and replay are
covered separately by the existing promotion and restart tests.

## Admission and publication dependencies

The peer initializes a `BundleSource` that immediately publishes its bundle
and invokes gossip, trusted-root, MSP and Gateway cache callbacks. Its normal
configuration path updates that source before the proposed activation
transaction has completed. A protected peer therefore needs a staged source,
an authenticated ledger-backed controller and generation leases at dispatch
before it can be started safely.

A protected peer commit adapter now routes configuration blocks through the
activation controller using a staged operator approval read under the store
lock. It retains a generation lease for ordinary native commits and rejects
malformed or mixed protected blocks. Real-ledger tests exercise authorized
commit, TLS-root publication after the native commit, and quarantine when
approval is missing. A blocked-commit test checks that the generation does not
drain until the native operation stops. Peer channel creation now attaches
this adapter and a private validator source when the authenticated registry
selects the channel.

The peer now has a protected lifecycle assembly that binds separate private
validation and serving channels, the guarded committer and the staged resource
publisher to one controller. Publisher installation is serialized with
controller recovery, and the lifecycle's peer recovery refuses to open the
gate without a publisher. A real-ledger component test exercises candidate
validation, rejection of a candidate after private validation advanced,
publication failure, recovery and reconstruction with new peer
objects after ledger reopen in the same process. Channel creation checks the
genesis anchor and reconciles the committed config block against world state
before exposing the serving channel. The real-ledger join test also checks
that an unapproved genesis never creates a ledger. Managed peers authenticate
the supported signed snapshot format before scheduling import. Trusted startup
supplies the registry and opens the ledger manager at the manifest's ledger
directory.
Staged peer configuration failures close admission while the store is locked,
and the lifecycle publisher resets the private validation source to the
authenticated committed bundle before admission can reopen. Malformed block
shape also closes admission in the protected committer.

The peer's endorsement adapter now acquires its identity deserializer from
the serving generation and holds the generation lease through endorsement
work. A closed generation rejects the result, and closed admission rejects
dispatch. For protected calls,
the peer gRPC stats handler retains the lease through the server RPC end after
the unary send; a missing or streaming response scope fails closed. A real
gRPC component test holds response serialization open after the handler returns and checks an
authenticated activation gate cannot drain until the send stops. The native
peer test makes signed QSCC and channel-less CSCC queries, kills the peer,
and leaves a durable commit-pending journal using a failed commit callback.
The restarted peer aborts that transition, serves the original configuration,
and stops serving protected queries on a subsequent restart with persisted
quarantine.

`comm.PrepareTrustedRootsForChain` now builds an isolated per-channel TLS-root
snapshot and `PublishTrustedRootsForChain` installs it explicitly. Preparation
does not mutate active credential support, and a component race test checks
failure and unrelated-channel behavior. The peer previews the aggregate roots
and validates the server trust-pool update before publishing the credential
snapshot; a component test checks that a failed server update leaves the
snapshot unchanged. The existing baseline callback still prepares and
publishes immediately. The protected channel controller uses staged
publication instead.

The Gateway now registers a protected staging function with the peer. An
activation publication hook prepares TLS and registered cache candidates
before publishing them and propagates publication or retirement errors. A
real-ledger component test exercises a failed cache publication, closed
admission and successful recovery retry. Gateway registers its stage before
peer channel loading, so protected recovery reconstructs the cache under
closed admission. Registration rejects both a channel under creation and an
already-serving protected channel. The publication barrier also prevents a
stage from being inserted between publication and admission. Gateway unary
RPCs cancel admitted work on generation closure, join outstanding workers
and retain the lease through the response. Routed protected calls require
an authenticated strict transport policy. Protected event streams require a
strict listener with a revocable connection. Generation closure interrupts the
ledger iterator and closes the underlying connection to unblock an HTTP/2
flow-controlled send. Multiplexed calls on that connection reconnect.

Managed startup supplies the authenticated policy to the shared listeners,
peer gossip and delivery clients, and orderer cluster clients and listeners.
The chaincode listener uses a local ML-DSA-65 CA and mutual TLS, including the
issued shim credentials. External chaincode clients require strict mutual TLS.
Protected participation admin requires a strict ML-DSA-65 endpoint and
verified client certificates.
The managed operations HTTP listener uses the same authenticated transport
profile. Configure an ML-DSA-65 serving certificate and key, enable required
client authentication, and provide trusted client roots. TLS 1.3 with
X25519MLKEM768 and a verified ML-DSA-65 client identity are required for all
operations requests, including health, metrics and version. Managed peers and
orderers reject an enabled Go profiling listener during startup. Network
exposure and the full endpoint inventory still require deployment validation.

Gateway prepares orderer endpoints separately from publication. Its orderer
cache is scoped by channel, MSP and TLS roots. Protected publication parses
the TLS candidate and retires stale orderer and endorser connections while
the old endpoints and TLS roots are still published and channel admission
is closed. A failed retirement leaves the candidate private. Retry closes
remaining stale connections and publishes the prepared roots and endpoints
before the gate reopens. Shared root aggregation and the per-channel cache
keys preserve resources for unrelated channels. Managed orderers prepare
all listener pools and validate dialer roots before installing either.

Gateway component race tests also cover publication of an empty endpoint
snapshot without falling back to discovery, and ensure a failed connection
retirement does not make the old TLS configuration current again.
After the cluster enqueue change, the full cluster package race tests, strict
transport feasibility tests and focused PQ4.0D restart tests passed locally.

The Gateway cache change is active for baseline channels too. A root rotation
can therefore replace a connection even when its network address is unchanged;
channels sharing an address now retain separate cached connections.

The orderer's protected registrar suppresses initial shared callbacks and
invokes them through the activation controller after authorization. The
focused callback test does not prove atomic TLS-root and cached-connection
publication. Broadcast holds the validated generation through readiness and
submission. Forwarding passes that generation into the cluster stream.
Local Raft submission transfers the lease to the pending batch and then to
the proposal queue. Waiting work releases its lease on generation closure.
The proposal worker reacquires the same generation before consuming a queued
block and retains its active lease until the cancellable Raft proposal call
returns. Raft can still apply entries it has already accepted. Durable config
preparation checks the expected generation under the activation store lock,
and replay still reconciles committed entries before reopening admission.
A managed subprocess proof submits approved config updates to a native
orderer through Broadcast and participation HTTP over strict TLS. It cancels
prior-generation Deliver streams, recovers the updated ledger after restart,
and rejects startup with a missing checkpoint.
The proof also rejects classical key exchange on participation admin.
A native managed peer joins an enrolled genesis over strict mutual TLS and
reloads the protected channel after restart. These tests run as subprocesses
without installing or starting the systemd service on a VM.

## Hosted CI evidence

On `97432ab056573751706bf836b29b29f512554940`, [Verify Build](https://github.com/vignatov/fabric-pq/actions/runs/45642425332)
passed all 16 jobs, including four gossip specs and protected cross-channel
shim revocation. [PQ3 isolated acceptance](https://github.com/vignatov/fabric-pq/actions/runs/45642425434)
also passed. The workflow records Go, FIPS mode, Linux runner and managed
binary hashes in [the PQ4.0E job](https://github.com/vignatov/fabric-pq/actions/runs/45642425332/job/139304362418).

On `fec4e82450d596eedb397afd46c91b3f0aa2182b`, [Verify
Build](https://github.com/vignatov/fabric-pq/actions/runs/45611609486) passed
all 16 jobs, including the disposable VM socket inventory and four gossip
specs. [PQ3 isolated acceptance](https://github.com/vignatov/fabric-pq/actions/runs/45611607502)
passed.

On `1d72a346b63b2fbcf16a00d265775f2710133181`, [Verify
Build](https://github.com/vignatov/fabric-pq/actions/runs/45601768505) passed all
16 jobs, including the disposable VM proof and all four gossip specs.
[PQ3 isolated acceptance](https://github.com/vignatov/fabric-pq/actions/runs/45601768488)
passed.

On `090e1e32518ee8216095d589e1ebb4b0242a730c`, [Verify
Build](https://github.com/vignatov/fabric-pq/actions/runs/45591052388) passed all
16 jobs and [PQ3 isolated acceptance](https://github.com/vignatov/fabric-pq/actions/runs/45591052391)
passed. All four gossip specs passed in the discovery, gossip, devmode and
pluggable integration group.

On `ca69d0bfa9fadabf665fc9c1e3de51881fdbe289`, [Verify
Build](https://github.com/vignatov/fabric-pq/actions/runs/45538028549) passed all
16 jobs, including Basic Checks, focused PQ4 jobs, unit tests and all nine
integration groups. All four gossip specs passed. [PQ3 isolated
acceptance](https://github.com/vignatov/fabric-pq/actions/runs/45538028547)
passed. The PQ4.0E job built native peer and orderer binaries and ran the
managed restart tests with Go 1.27.4, `GOFIPS140=off` on Ubuntu 24.04 amd64.
The job did not record native binary hashes. [Independent
review](https://github.com/vignatov/fabric-pq/pull/12#pullrequestreview-6055170765)
confirmed the results and left the milestone gates incomplete.

## Managed operations regression evidence

On 2026-11-25, the isolated Ubuntu Linux/amd64 runner used Go 1.27.4 with
`GOFIPS140=off` for the managed operations follow-up. Both native restart
tests verified strict mTLS on the operations listener before and after
restart, classical key exchange and missing client certificate rejection,
and startup rejection for disabled operations TLS and enabled profiling.
Race-enabled launcher, HTTP, operations, peer startup and orderer server
packages passed, as did vet for those packages.

| Native test binary | SHA-256 |
| --- | --- |
| Peer | `ba71e76c768670d26faf3e49fbb297032e1a929cf2354c697b5e856eb7d9195e` |
| Orderer | `0ed86c4049f92c3f10b4593ad297aeaacd0cefe86c801c11fc5ecbed2ea9f6b1` |

## Earlier focused evidence

On 2026-11-24, a Linux/amd64 Ubuntu WSL2 copy of the dirty worktree based on
`f1e604f01c1ce4899466e91ae4a5fc62711cb6bc` used Go 1.27.4 and
`GOFIPS140=off`. The Go binary SHA-256 was
`de0ae3e082ce7599eae4fb69fa2ef1e43b8f31ffd3fce62cdf81930aa9005050`;
the test binaries were temporary and their hashes were not recorded.
Race-enabled policy, enrollment, launcher, PQ4.0E orderer,
PQ4.0C peer/orderer activation, PQ4.0D native Raft recovery, strict transport
feasibility, broadcast, deliver, follower and etcdraft package tests passed.
Affected-package `go vet` passed. These are local results, not final-commit CI
evidence. The PQ4.0D run failed with the attempted Raft cancellation change;
the full focused PQ4.0D regression passed once after that change was removed,
but subsequent promotion tests also failed without the change. That local
session did not run the full Verify Build, integration or PQ3 suites.

After adding the bounded broadcast validation lease, the broadcast race tests
and affected-package vet passed; full peer, endorser and Gateway package race
tests also passed. Orderer server, local configuration, cluster and channel
participation package race tests passed. TLS-root staging and strict transport
feasibility race tests passed after the credential support refactor. One full
multichannel race run failed with
output too large to identify the failing case; a captured full rerun passed.
A later captured `GOMAXPROCS=4` run failed in
`TestPQ40DProtectedParticipationPromotion`, waiting for configuration block 2;
an isolated run at the same setting also failed. A diagnostic repeat using
`go test -count=2` was invalid because Ginkgo requires `-count=1`. These runs
do not establish the cause of the first failure or prove that the remaining
end-to-end handoff is safe.

The isolated promotion timeout also reproduced with `GOMAXPROCS=8`. In one
failure log, leadership changed while node 4 was being added, and Raft logged
that leaders ignored the node-4 configuration-change proposal because a prior
configuration change was still unapplied. Protected leaders now retry the
membership change derived from the committed authorized configuration while
keeping admission closed until Raft applies it. The protected promotion test
passed five consecutive race-enabled runs with retry messages observed; the
focused PQ4.0D and etcdraft race suites also passed. This is local evidence,
not proof of all leadership and network-failure cases. Replay readiness and
membership authorization remain mandatory.

The host Docker daemon was reachable, but Docker Desktop integration was not
enabled for the temporary WSL test distribution. An isolated container with
the existing Docker socket ran the baseline Raft participation case for a
non-genesis consenter join successfully. One initial attempt failed during
setup because the container user could not access the socket; rerunning as root
passed. This did not exercise protected peer or orderer admission. Automatic
approval review rejected a full Raft-suite attempt because it combined a root container,
the host Docker socket and a broad writable host `/tmp` mount. An appropriately
isolated Linux runner with Docker integration is needed for that matrix.
After explicit user approval, the development checkpoint was uploaded as draft
PR 12 for hosted Linux CI. The results must be checked against the exact tested
commit and do not replace the missing protected service-path integration.
On commit `dbf930a`, Verify Build and all nine integration matrix jobs passed.
On commit `1182150`, PQ3 isolated acceptance, Basic Checks, unit tests, all
PQ4-focused jobs and eight integration matrix jobs passed. The gossip matrix
job failed in a state-transfer test while a peer expected block 6 but received
block 11; the cause is unconfirmed and its hosted rerun passed. Neither
run establishes protected process readiness.

On commit `c99417e`, the hosted unit suite failed because snapshot quarantine
could close the Raft node before its accepted request returned the specific
authorization error. The failure remained fail-closed. The handler now reports
the failure after quarantine but before stopping Raft; a deterministic
race test and repeated native snapshot regression passed locally. Final-head
hosted CI is still required.

On commit `96fe597`, the unit job failed in `TestStoreFilterPurgedKeys` after
the block-zero background purge ran during the filter-only assertions. The
test now holds the purge lock through those assertions and waits for the
scheduled purge before cleanup. Ten isolated race-enabled repetitions and the
private-data storage package race suite passed locally. A separate hosted
integration job failed during setup because `softhsm2` was unavailable; its
tests did not execute in that job. The setup script now refreshes package
indexes before installation. Final-head hosted CI remains required.

On commit `212ab45`, the hosted Raft integration job failed after a restarted
orderer tried to snapshot ledger index 11 while its in-memory Raft log ended at
index 7. Replayed blocks alone triggered snapshot scheduling before the Raft
log caught up. The scheduler now requires a newly applied block while preserving
the replayed-byte snapshot interval, with a focused regression test. This is a
baseline Raft fix as well as a protected-path regression; hosted integration
must rerun on the final head.
