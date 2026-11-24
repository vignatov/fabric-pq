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
| Peer bootstrap and endorsement, Gateway and background admission | Incomplete |
| Peer native commit adapter with staged approval | Real-ledger race tests passed; not selected by peer startup |
| Orderer service, stream and follower integration under strict transport | Incomplete |
| Orderer broadcast validation generation lease | Validation lease and cancellation-aware Raft readiness implemented; end-to-end handoff remains incomplete |
| Cluster send cancellation and shutdown reporting | Component race tests passed; protected handoff and lease ownership remain incomplete |
| End-to-end orderer generation lease | Incomplete; protected Raft forwarding uses a generation-bound stream, but validation and local submission are not continuously leased |
| Protected Raft membership retry | Implemented; focused race and repeated promotion tests passed |
| Staged shared TLS resources and crash/restart reconstruction | Incomplete |
| Peer credential roots preparation and publication failure | Component race tests passed; protected lifecycle integration remains incomplete |
| Gateway orderer cache preparation and TLS-scoped retirement | Component race tests passed; protected publication and dispatch remain incomplete |
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
drain until the native operation stops. Peer channel creation does not yet
construct this adapter: the private validator source, controller bootstrap,
protected service admission and activation-controlled TLS and Gateway
publication must be integrated first.

`comm.PrepareTrustedRootsForChain` now builds an isolated per-channel TLS-root
snapshot and `PublishTrustedRootsForChain` installs it explicitly. Preparation
does not mutate active credential support, and a component race test checks
failure and unrelated-channel behavior. The peer previews the aggregate roots
and validates the server trust-pool update before publishing the credential
snapshot; a component test checks that a failed server update leaves the
snapshot unchanged. The existing baseline callback still prepares and
publishes immediately. Protected activation has not been wired to this API;
server TLS credentials and Gateway connection caches are not yet published by
an authenticated peer activation controller.

The Gateway now registers a protected staging function with the peer. An
activation publication hook prepares TLS and registered cache candidates
before publishing them and propagates publication or retirement errors. A
real-ledger component test exercises a failed cache publication, closed
admission and successful recovery retry. Production channel creation does not
yet install this hook on an authenticated controller or select the protected
committer; ordinary callbacks still publish baseline resources.
Gateway is created after existing peer channels are initialized. Protected
startup must therefore rebuild and publish each existing channel's Gateway
candidate under closed admission before Gateway can serve; registering the
stage alone does not reconstruct those caches. Registration and publication
are serialized, but this late-registration recovery path is not yet wired.

Gateway orderer endpoints can now be prepared without publishing them. Its
connection cache is scoped by channel, MSP and TLS roots; publishing a changed
snapshot retires stale connections, reports retirement errors for retry, and
rejects a connection created against a superseded configuration. Focused race
tests cover those behaviors and unrelated channels. A retirement error can be
used by an activation owner to keep admission closed, but the ordinary Gateway
callback still publishes immediately and only logs that error. The protected
peer activation controller does not yet own that callback. This is not an
end-to-end protected proof.

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
publication. Broadcast holds an authenticated serving generation during
validation, releases it before the potentially blocking Raft handoff, and
checks that generation again before enqueue. It does not hold a serving
generation for the whole operation. Protected Raft readiness waits now observe
the validation generation and return when it closes. Forwarding acquires the
then-current generation and uses the generation-bound stream send, which holds
its own lease until the accepted send stops. Validation and local submission
do not yet carry a single generation through to forwarding. A proposed Raft
submission cancellation change was removed after a native participation-promotion regression failed.
The failure also reproduced later with that change absent, so its cause has
not been established.
The cluster stream has a context-aware enqueue, checks queued work for
cancellation, and cancels an in-flight send by closing its stream before
reporting completion. Stream shutdown reports accepted queued work and
unblocks a full queue. The protected broadcast/Raft path does not yet use this
API or retain a generation lease through its completion report. Cancellation
also cannot retract work already handed to the consensus queue.
The stream additionally offers a generation-bound send that rejects a stale
generation and holds its own lease until a queued or in-flight send stops.
Closing that generation cancels the channel-scoped stream. Linux race tests
check queued-send drainage, in-flight transport drainage and rejection after
the gate reopens. Cluster RPC
can carry that generation through a submit send without allowing a stale caller
to evict a current stream. This path is not connected to broadcast or Raft and
does not establish end-to-end safety.
Adding a lease without addressing those boundaries could
deadlock an activation waiting for old work to drain. Deliver has existing cancellation
integration, but protected transport, stream-boundary and recovery evidence
remain incomplete. Managed protected startup must stay blocked until these
dependencies are addressed.

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
