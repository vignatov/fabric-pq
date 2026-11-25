# PQ4.0E bootstrap and admission: INCOMPLETE

This is a development checkpoint, not an authenticated node-enrollment
implementation or a protected deployment. Do not accept PQ4.0E or mark the
PQ4.0B enforcement gate complete on this evidence.

## Current boundary

When any orderer `General.PQActivation` field is configured, the registrar
opens the configured activation store, authenticates the policy embedded in
its checkpoint against the configured signer and node/network identity, and
derives channel membership from that policy. The ordinary channel list cannot
remove a binding; a listed channel absent from the policy is an error. The
registry rejects corrupt journals and durable channel records that no longer
correspond to a policy binding. Channel recovery, replay readiness and
quarantine remain separate requirements.

The orderer process currently rejects configured protected startup before
listener initialization because strict transport is not integrated across
all required endpoints. Direct registrar tests do not establish protected
process readiness. Baseline startup with all activation settings absent keeps
its previous path.

**Critical unresolved downgrade:** ordinary local configuration can still
remove *all* activation settings when Fabric is started directly. The new
Linux launcher verifies signed enrollment and history and refuses protected
startup. A fixed systemd unit is provided, but it has not been installed or
verified on a managed VM. Therefore
the registry is not non-bypassable in a deployed VM, and this change must not
be treated as a security boundary.

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

For protected mode, the launcher also verifies the pinned policy signer and
authenticates the active policy/checkpoint before returning an explicit
startup error. No protected peer or orderer process is launched yet. For a
valid baseline declaration it replaces itself with the signed executable and
arguments on Linux. Other platforms fail closed.

## Remaining work and evidence

| Property | Status |
| --- | --- |
| Configured registry derives membership from authenticated checkpoint | Focused Linux race tests passed; managed bootstrap incomplete |
| Reject configured protected orderer before listener initialization | Focused Linux race tests passed; end-to-end process startup incomplete |
| Signed manifest, protected history and Linux launcher | Linux race and subprocess tests passed; managed deployment incomplete |
| Fixed managed systemd unit and installer | Provided; VM installation and verification incomplete |
| Non-bypassable managed VM deployment and protected-to-baseline prohibition | Incomplete: protected service installation and provisioning lifecycle required |
| Authenticated onboarding and non-genesis join provenance | Incomplete |
| Peer bootstrap and endorsement, Gateway and background admission | Channel creation selects the controller from an authenticated registry when supplied by trusted startup; managed startup and other admission remain incomplete |
| Peer native commit adapter with staged approval | Real-ledger race tests passed; protected channel creation installs the adapter |
| Protected peer lifecycle assembly | Protected channel creation recovers private validation, serving publication and guarded commits before exposing the channel |
| Orderer service, stream and follower integration under strict transport | Incomplete |
| Orderer broadcast validation generation lease | Broadcast holds the validated generation through cancellable readiness and submission |
| Cluster send cancellation and shutdown reporting | Forwarding retains the exact submit generation through the stream handoff |
| Orderer Raft generation lease | Local submission transfers admission through the pending batch and proposal queue to the Raft proposal call |
| Protected Raft membership retry | Implemented; focused race and repeated promotion tests passed |
| Staged shared TLS resources and crash/restart reconstruction | Incomplete |
| Peer credential roots preparation and publication failure | Component race tests passed; protected lifecycle integration remains incomplete |
| Gateway cache publication and admission | Protected unary admission, strict routed transport and revocable event streams wired |
| Orderer protected bundle callbacks | Focused Linux race test passed; TLS and cache publication proof incomplete |
| Full service-path and shared-resource inventory | Incomplete |
| Full regression, integration and final-head CI evidence | Incomplete; see focused evidence below |

Complete privileged-host replacement or rollback of all protected
provisioning state remains outside the development threat model.

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

When startup supplies an authenticated transport policy, the peer's gossip
and orderer delivery clients inherit it. The orderer's cluster dialer and
separate cluster listener inherit the general listener's authenticated policy.
Managed startup still needs to supply that policy and validate the remaining
required endpoints before listening. The chaincode listener and participation
admin paths still require integration or explicit exclusion from the protected
service.

Gateway prepares orderer endpoints separately from publication. Its orderer
cache is scoped by channel, MSP and TLS roots. Publication retires stale
connections, reports retirement errors for retry, and rejects a connection
created against a superseded configuration. Strict Gateway endorser
connections are scoped by channel and retired during protected publication,
so subsequent calls reconnect with the approved TLS roots.

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
Deliver stream coverage and managed strict transport remain incomplete.

## Focused evidence

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
but subsequent promotion tests also failed without the change. Full
Verify Build, integration and PQ3 acceptance have not run.

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
passed. This does not exercise protected peer or orderer admission, and the
full Docker-dependent integration suites remain unrun. Automatic approval
review rejected a full Raft-suite attempt because it combined a root container,
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
