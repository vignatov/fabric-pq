# PQ4.0E bootstrap and admission: INCOMPLETE

This development checkpoint demonstrates authenticated enrollment of native
node subprocesses. PQ4.0E and the PQ4.0B enforcement gate remain incomplete
pending the deployment and runtime evidence below.

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

**Critical unresolved downgrade:** ordinary local configuration can still
remove *all* activation settings when Fabric is started directly. The new
Linux launcher verifies signed enrollment and history and rejects invalid
protected startup evidence. Non-bypassability depends on the trusted VM
provisioner and service manager controlling every authorized node launch.
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
These installation and permission requirements are not yet implemented or
verified by deployment automation. Unmanaged Fabric remains a separate path.

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
| Authenticated onboarding and non-genesis join provenance | Signed orderer participation target and peer snapshot at an authenticated configuration block |
| Peer bootstrap and endorsement, Gateway and background admission | Managed peer startup installs the verified channel registry and strict shared listener |
| Peer native commit adapter with staged approval | Real-ledger race tests passed; protected channel creation installs the adapter |
| Protected peer lifecycle assembly | Protected channel creation recovers private validation, serving publication and guarded commits before exposing the channel |
| Orderer service, stream and follower integration under strict transport | Incomplete |
| Orderer broadcast validation generation lease | Broadcast holds the validated generation through cancellable readiness and submission |
| Cluster send cancellation and shutdown reporting | Forwarding retains the exact submit generation through the stream handoff |
| Orderer Raft generation lease | Local submission transfers admission through the pending batch and proposal queue to the Raft proposal call |
| Protected Raft membership retry | Implemented; focused race and repeated promotion tests passed |
| Staged shared TLS resources and crash/restart reconstruction | Incomplete |
| Peer credential roots preparation and publication failure | Fallible cache retirement precedes TLS and endpoint installation while protected admission is closed |
| Gateway cache publication and admission | Protected unary admission, strict routed transport and revocable event streams wired |
| Orderer protected bundle callbacks | Managed orderer stages listener and cluster dialer trust before publishing either |
| Full service-path and shared-resource inventory | Incomplete |
| Managed operations listener and profiling | Authenticated strict mTLS for operations; managed startup rejects an enabled profiling listener |
| Full regression, integration and final-head CI evidence | All hosted jobs passed at `1d72a34`; later changes require their own exact-commit runs |

Complete privileged-host replacement or rollback of all protected
provisioning state remains outside the development threat model.

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
file containing the target configuration block. Sign the payload with
domain `fabric-pq/peer-snapshot/v1` and a NUL separator. The payload also
includes `signable_metadata_hash` and `additional_metadata_hash`, the raw
SHA-256 digests of both native snapshot metadata files. This authenticates
the exact state-transfer boundary and checks the current checkpoint binding
before asynchronous import. The peer copies and verifies the approved files
in a private directory. Snapshot height and hash must match the target
configuration block. Recovery re-authenticates the metadata retained by the
native ledger and checks the ledger linkage and persisted world-state
configuration before admission can open.

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
that an unapproved genesis never creates a ledger. Enrolled peers reject
snapshot imports until their provenance can be checked before import.
Trusted startup must supply the registry and open the ledger manager at the
manifest's ledger directory. Managed protected startup and a fresh-process
reconstruction test remain pending.
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
authenticated activation gate cannot drain until the send stops. Endorsement
tests exercise the handoff. A protected
process-level response and interrupted-transition test remains required.

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
A managed subprocess proof uses a native orderer to submit an approved config
update over strict TLS, cancel a prior-generation Deliver stream, recover the
updated ledger after restart, and reject startup with a missing checkpoint.
The proof also rejects classical key exchange on participation admin.
A native managed peer joins an enrolled genesis over strict mutual TLS and
reloads the protected channel after restart. These tests run as subprocesses
without installing or starting the systemd service on a VM.

## Hosted CI evidence

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
