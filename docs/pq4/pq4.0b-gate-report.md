# PQ4.0B gate report: INCOMPLETE

**Recommendation: stop for architecture review; do not accept or merge the
gate.** The focused `comm` and signed-policy components are not a protected
Pactway network. `PactwayPQTransportV1` is the selected name and
fresh-genesis-only contract; it is **not implemented or advertised as
supported** by peer or orderer binaries. The existing enrollment capability
and baseline behavior remain separate.

## Evidence provenance

- Base commit: `4a3a45f0cd3b5d6005d996a92cb1ae30801bc3a7`. The local tests
  below ran on a dirty worktree based on this commit, with the PQ4.0B component
  and lifecycle-test changes present. They are not evidence for the base
  commit alone.
- Environment: WSL Ubuntu 24.04, Linux amd64, Go 1.27.4, `GOFIPS140=off`,
  vendored dependencies and `GOFLAGS=-buildvcs=false`.
- CI head: `1d5721572a5d3a7150d29ae2ae48dfc1a767ae60`, Go 1.27.4
  (`linux/amd64`). GitHub Actions run
  [45066471753](https://github.com/vignatov/fabric-pq/actions/runs/45066471753)
  completed successfully, including Basic Checks, PQ4.0 Feasibility, the
  PQ4.0B component checks, unit tests and all Verify Build integration jobs.
  PQ3 isolated acceptance run
  [45066471774](https://github.com/vignatov/fabric-pq/actions/runs/45066471774)
  also completed successfully; both temporary and permanent profile
  acceptance steps and protected-evidence verification passed.
- CI status above means the configured workflows passed; it does not upgrade
  any network-wide PQ4 proof below from INCOMPLETE.
- No peer, orderer, `osnadmin` or chaincode-server binary was built or
  identified for these PQ4.0B component results. The Go test binaries were
  ephemeral and their hashes were not recorded. Binary provenance for the
  required live-network and unsupported-binary proofs is **INCOMPLETE**.
- The policy verifier receives the trusted signer, checkpoint and
  network/node identity from its caller. The test creates ephemeral keys; it
  does not demonstrate protected on-disk provisioning, durable freshness or
  restart recovery. Complete privileged-host rollback is excluded from the
  isolated-development threat model.

## Component observations

An actual Fabric `comm` server and the `comm.ClientConfig` constructor
completed gRPC health requests under an authenticated test policy. On both a
server-authenticated listener and an mTLS listener, the client observed
TLS 1.3, X25519MLKEM768 and a normally verified ML-DSA-65 server leaf.
The mTLS listener also observed a verified ML-DSA-65 client leaf. The
server-only listener did not authenticate a TLS client. Test certificates
were issued by an ephemeral ML-DSA-65 CA. The tests constrain the endpoint
leaf key, not CA or intermediate key/signature algorithms; this is not proof
of a quantum-resistant PKI path. No TLS secrets or private keys were recorded.

Both listener variants rejected TLS 1.2 with an unsupported-version
diagnostic and X25519-only key exchange with a no-common-key-exchange
diagnostic. The mTLS listener rejected a classical client identity and a
missing client certificate with their respective diagnostics. A strict client
rejected a classical server identity, wrong hostname and untrusted CA.
Replacing the strict server's identity with a classical certificate caused
subsequent handshakes to fail. A separate test performed actual handshakes
through both original and cloned server credentials and confirmed that neither
accepted TLS 1.2 or classical-only key exchange. Recreating the component
listener on the same address with the same in-memory policy again negotiated
TLS 1.3 and X25519MLKEM768 with a verified ML-DSA-65 server, and rejected an
X25519-only client with a key-exchange diagnostic. This is not a process
restart or a demonstration that the policy is reloaded from protected state.

The operator-transition verifier rejects tested stale, replayed, skipped,
conflicting, unauthorized and weakened transitions and leaves the current
in-memory policy unchanged. Its candidate is a synthetic protobuf, not an
authenticated Fabric update. The verifier does not prepare a durable
transition, verify Fabric authorization, commit a checkpoint, or recover
after a crash.

## Required proof matrix

Each result applies to the **requested gate**, not merely the component test.

| Required proof | Result | Evidence or missing work |
| --- | --- | --- |
| Actual Fabric `comm` listener rejects TLS 1.2 and classical KEM | PASS | Component test and cause-specific server diagnostics above. |
| Approved ML-DSA server identity and hybrid KEM | PASS | Verified chain, endpoint key, TLS version and group on the component listener. |
| Required mTLS and classical/missing client rejection | PASS | Component mTLS listener only; endpoint-specific proofs remain below. |
| Signed bootstrap before actual node readiness and protected checkpoint | INCOMPLETE | Verifier tests only; no protected state loader or peer/orderer startup integration. |
| Identity binding and stale/conflicting bootstrap rejection | INCOMPLETE | Caller-supplied checkpoint and identity reject these inputs in component tests; not proven against node startup and protected storage. |
| No downgrade through clones, credentials and restarts | INCOMPLETE | Component clones, listener recreation, server-certificate replacement and direct server credential factory tested; real node restart and all credential factories untested. |
| Actual authenticated capability, local agreement and channel join | INCOMPLETE | Capability not implemented; no actual node/channel-policy integration. |
| Fabric-authorized downgrade or removal rejected | INCOMPLETE | No actual PQ4 channel or authenticated configuration update. |
| Authorized non-weakening Fabric and operator transition, durable recovery | INCOMPLETE | Operator-only synthetic-config verification; no Fabric authorization, protected journal or prepare/commit/restart proof. |
| Older peer and orderer reject the actual capability | INCOMPLETE | No actual capability or binary provenance for this proof. Earlier unknown-name evidence is not a substitute. |
| Actual peer and orderer listeners and outbound constructors | INCOMPLETE | No node startup, transport-policy propagation or process-level handshake test. |
| Shared listener serving a PQ4-required channel | INCOMPLETE | Weak clients were rejected by a component listener, but it hosted no Fabric channel. |
| Real CCAAS metadata, strict mTLS and registration | INCOMPLETE | Existing CCAAS component remains a baseline feasibility test, not strict policy enforcement. |
| Actual orderer administration and `osnadmin` strict mTLS | INCOMPLETE | Existing HTTP feasibility components are not an orderer listener or strict `osnadmin` integration. |
| No private keys in distributable CCAAS packages | INCOMPLETE | No strict CCAAS package was created or examined. |
| PQ3.5 temporary/permanent acceptance | PASS | The PQ3 isolated acceptance workflow passed both `rfc5612-test-only-v1` and `pactway-hybrid-certificate-v1`, including protected-evidence verification, on this head; see run [45066471774](https://github.com/vignatov/fabric-pq/actions/runs/45066471774). |
| Existing PQ4.0 regression | PASS | Full feasibility package passed locally with the component changes. |
| Baseline Raft rollback characterization | INCOMPLETE | Not rerun for this worktree; its earlier observed panic is not PQ4 protection. |
| Dedicated full acceptance CI and independent review | INCOMPLETE | The Verify Build, PQ4.0 Feasibility, PQ4.0B Component Checks and PQ3 isolated acceptance workflows passed on this head. The PQ4.0B workflow covers components only; full network acceptance and independent review have not occurred. |

### Negative-case accounting

| Required case | Gate result | Current boundary |
| --- | --- | --- |
| 1. Missing bootstrap policy | INCOMPLETE | In-memory verifier rejects it; node startup is not wired. |
| 2. Invalid signature | INCOMPLETE | Verifier rejection tested; node startup is not wired. |
| 3. Stale/conflicting checkpoint | INCOMPLETE | In-memory verifier rejection tested; protected durable state is absent. |
| 4. Wrong network/node | INCOMPLETE | Verifier rejection tested; independent node provisioning is absent. |
| 5. Classical-only KEM | PASS | Real strict `comm` listener and cloned credentials reject with key-exchange diagnostics. |
| 6. TLS 1.2 | PASS | Real strict `comm` listener and cloned credentials reject with version diagnostics. |
| 7. Classical-only endpoint identity | PASS | Component strict client and mTLS server reject classical identities. |
| 8. Missing required client identity | PASS | Component mTLS server rejects a missing client certificate. |
| 9. Missing/inconsistent channel capability | INCOMPLETE | Capability and actual binding not implemented. |
| 10. Authorized configuration weakening PQ4 | INCOMPLETE | No Fabric-authorized PQ4 configuration update tested. |
| 11. Unsupported peer and orderer | INCOMPLETE | No actual new capability or recorded binaries. |
| 12. Plaintext CCAAS metadata | INCOMPLETE | The earlier plaintext guard is test-only, not runtime enforcement. |
| 13. Policy loss on restart or credential recreation | INCOMPLETE | Credential clone/replacement and component listener recreation are tested; process restart and policy persistence are not. |
| 14. Weak client on a shared strict listener | INCOMPLETE | Component listener rejects weak clients but serves no hosted channel. |

## Lifecycle review stop

The actual orderer `BlockWriter` publishes the new bundle before appending
the configuration block. `TestGoodWriteConfig` observes ledger height 1 at
bundle publication and height 2 in the post-append activation callback.
The orderer's block metadata also reads the active configuration sequence
when writing the block; simply moving the bundle update after append would
change that behavior. On the peer, configuration application occurs during
block validation, before `StoreBlock` retrieves private data and commits the
block. Bundle callbacks immediately update dependent resources.

The current implementation has no reviewed barrier tying those activation
points to the signed preparation, durable Fabric commit and protected local
checkpoint. A post-commit-only checkpoint callback cannot establish that an
unauthorized or inconsistent configuration was never exposed. A proposed
solution must specify and test peer and orderer pre-activation authorization,
concurrent channel use, leader/follower behavior, durable journal ordering,
and recovery for crashes before and after each ledger/checkpoint write.
On an unauthorized committed configuration it must persistently fail closed
across restart, rather than resume serving the earlier channel state. This is
an architecture-review request, not a finding that a safe design is
mathematically impossible. The candidate lifecycle protocol and required
falsification tests are captured in the [configuration activation
ADR](adr-config-activation.md), whose status is proposed and unapproved.

The independently constructed gossip credentials and Gateway connection
factory also do not carry the new policy; Gateway can select plaintext when
roots are absent. Proving all participating peer/orderer outbound paths
requires the corresponding PQ4.3 transport propagation. A bounded candidate
deferment is to prove only explicitly enumerated peer/orderer, delivery and
gossip paths in an isolated network and list all others as uncovered; it
requires separate approval and cannot count as full-network protection.

CCAAS metadata/runtime, the shim server, admin HTTP and `osnadmin` each need
the PQ4.4 endpoint enforcement. A bounded candidate is a strict, runtime-keyed
CCAAS registration stream and the actual orderer admin API with strict
`osnadmin`, independently tested for every specified negative case. It also
requires separate approval if deferred; both proofs are mandatory for this
gate and therefore remain INCOMPLETE.

## Executed commands

All commands below ran in the environment above. Package arguments are Go
import paths.

```text
GOFIPS140=off GOFLAGS=-buildvcs=false go test -mod=vendor -race -count=1 github.com/hyperledger/fabric/internal/pkg/pqtransport github.com/hyperledger/fabric/internal/pkg/comm github.com/hyperledger/fabric/integration/pq4/feasibility
PASS
GOFIPS140=off GOFLAGS=-buildvcs=false go vet -mod=vendor github.com/hyperledger/fabric/internal/pkg/pqtransport github.com/hyperledger/fabric/internal/pkg/comm github.com/hyperledger/fabric/integration/pq4/feasibility
PASS
make linter
PASS (0 issues in ./... and ccaas_builder)
GOFIPS140=off GOFLAGS=-buildvcs=false go test -mod=vendor -race -count=1 -run "^TestFabricCommServerCredentialsPreserveTLSMinimum$|^TestStrictServerCredentialsClone$|^TestAuthenticatedPolicyFabricComm$|^TestStrictCommListenerRestart$" github.com/hyperledger/fabric/integration/pq4/feasibility github.com/hyperledger/fabric/internal/pkg/comm
PASS
GOFIPS140=off GOFLAGS=-buildvcs=false go test -mod=vendor -race -count=10 -run "^TestStrictCommListenerRestart$" github.com/hyperledger/fabric/integration/pq4/feasibility
PASS
GOFIPS140=off GOFLAGS=-buildvcs=false go test -mod=vendor -count=1 -run ^TestGoodWriteConfig$ github.com/hyperledger/fabric/orderer/common/multichannel
PASS
```

Intermediate focused runs failed to compile because of a syntax error and an
unused variable during test edits. Both were corrected and the relevant
race-enabled tests above passed afterward. Network acceptance, unsupported-binary tests and the Raft rollback test were
not run locally. Full Verify Build and PQ3 temporary/permanent profile
acceptance ran in GitHub Actions and passed on the commit above; this does
not provide the missing network-wide PQ4 evidence.

The first PR `Basic Checks` run failed on two lint rules for one integer loop
and one direct protobuf field access. These were changed to integer range and
the generated `GetSequence()` accessor. A follow-up local `make linter` run
reported zero issues in both the root module and `ccaas_builder`. The old
TLS-minimum feasibility test also encoded the prior constructor downgrade;
it now verifies that original and cloned credential factories preserve an
explicit TLS 1.3 minimum and report the matching `Info()` version.

## PQ4.0C activation proof

**Architecture status: INCOMPLETE.** The scope of this follow-up is the local
write-ahead protocol and native lifecycle seams. Node startup, channel RPC and
background admission, and consensus runtime stay on their existing paths.

| Property | Evidence and scope |
| --- | --- |
| Independent Fabric and operator authorization | The peer proof uses a real MSP-signed update, V20 config validation and `Channel.Apply` on a private bundle. It exercises both authorizations, each alone and a native commit without an authorization journal. Existing policy tests cover profile downgrade, stale versions and conflicting digests. |
| Serving visibility and native peer restart | The peer proof separates the private config validator and public `BundleSource`; its actual committer callback observes the previous serving bundle. The reopened kvledger config block and state DB must agree before startup publication. The proof tests a matching and mismatching binding after genesis initialization. |
| Native orderer metadata | The orderer proof uses the real synchronous writer and file ledger, checks config sequence, last-config metadata, the real block signature and Raft metadata bytes, and verifies the following block. It exercises a gate lease that is cancelled and drained before append. |
| Raft leaders, followers and startup | The proof models the replay-complete input and exercises the shared native writer. Production coverage still needs a guard before Raft membership/options mutation, a channel-local stop outcome owned by the Raft loop, and a native replay-complete signal. The direct follower append path also needs its guard. |
| Transport and cross-channel service behavior | PQ4.0B provides strict comm component tests. Full coverage requires generation checks in service readers, callback staging, approved shared trust resources, and listener/dialer and connection-lifetime integration. |

### Process-crash matrix

`TestPQ40COrdererCrashRecovery` starts a separate test process for each row and
exits from the selected hook without defers. The parent reopens the local
Fabric ledger and protected store, runs recovery twice, and counts checkpoint
writes. All 15 subprocess cases passed in the first Linux proof run below.
Directory sync and rename hooks test process loss,
including a rename visible to the next process before directory sync. They do
not simulate power loss or interrupt a kernel write.

| Exit hook | Persisted state at exit | Recovery and serving decision |
| --- | --- | --- |
| Before prepare and after the prepared journal file sync before rename | Prior ledger and checkpoint; no installed journal | Match and serve the prior configuration. |
| After durable preparation | Prior ledger and checkpoint; PREPARED | Confirm the candidate is absent; record ABORTED and serve the prior configuration. |
| After durable commit intent and at native writer append entry | Prior ledger and checkpoint; COMMIT_PENDING | Confirm the candidate is absent once native replay settles; record ABORTED and serve the prior configuration. |
| After native append and after ledger directory sync | Candidate ledger block; prior checkpoint; COMMIT_PENDING | Revalidate both authorizations, advance exactly once and serve the candidate. |
| After syncing the checkpoint temporary file | Candidate ledger block; prior installed checkpoint; COMMIT_PENDING | Replace the old checkpoint once and serve the candidate. |
| After checkpoint rename and after directory sync | Candidate ledger block and new visible checkpoint; COMMIT_PENDING | Authenticate both and serve the candidate with zero additional checkpoint writes. |
| Before, during and after serving resource publication | Candidate ledger and checkpoint; COMMIT_PENDING | Rebuild publication from trusted state, then open the candidate generation. |
| After durable ACTIVE journal and after opening the gate | Candidate ledger, checkpoint and ACTIVE journal | Restore the active generation with zero additional checkpoint writes. |
| Peer commits without a preparation record | Candidate peer ledger and prior checkpoint | Persist quarantine, leave admission closed on repeated recovery. Covered by `TestPQ40CPeerActivation/committed_without_preparation`. |
| Simulated native commit error before or after append | COMMIT_PENDING and prior checkpoint, with either prior or candidate ledger | Keep admission closed on error and reconcile against the actual ledger. Both cases passed in `TestPQ40COrdererUncertainCommit`. |

### PQ4.0C test provenance

- Base commit `b91dd57c781f3ce5c848769e1a3ec3e87f7a4116`, verified against
  `origin/main` before branching.
- First proof commit `243d6d2a2b1ff2ed1d62f82b67e92227c36b0aa0` on Ubuntu
  24.04, Go 1.27.4, Linux amd64. The focused race tests and vet passed, and
  PQ4.0 Feasibility and PQ4.0B Component Checks passed. Basic Checks flagged
  one Go literal lint and skipped dependent Fabric tests on that run.
  [Verify Build 45081026724](https://github.com/vignatov/fabric-pq/actions/runs/45081026724).
- A Windows amd64 Go 1.27.4 check cross-compiled and vetted the Linux proof.
  Native Windows PQ4.0 feasibility and policy tests passed. The full existing
  `comm` suite failed `TestNewGRPCServerInvalidParameters` on Windows socket-error
  wording. The Linux PQ4.0B component job passed the `comm` suite.
- The **PQ4.0C Activation Proof** job records the exact tested commit, Go
  version, Linux runner and FIPS mode. It runs the following commands:

```sh
GOFIPS140=off go test -mod=vendor -race -count=1 -v -run '^TestPQ40C' ./core/peer ./orderer/common/multichannel ./internal/pkg/pqtransport/activation/...
GOFIPS140=off go vet -mod=vendor ./core/peer ./orderer/common/multichannel ./internal/pkg/pqtransport/activation/...
```

The existing Verify Build jobs cover Basic Checks, lint, PQ4.0 feasibility and
PQ4.0B components, and the Fabric unit and integration suites. PQ3 acceptance
runs in its existing workflow. A build or cross-compilation alone does not
establish a Linux crash-recovery result.
## PQ4.0D Raft quarantine and replay evidence

**Overall PQ4.0B gate remains INCOMPLETE.** See the
[native interception diagram, quarantine transitions, and replay contract](adr-config-activation.md#pq40d-native-orderer-lifecycle).

| Path | Production boundary | Evidence |
| --- | --- | --- |
| Raft leader | Verify staged approval before proposal and exact ordered block before native apply | Native restart harness exercises the real leader proposal and application paths. |
| Raft follower | Run the same ordered-block guard before changing block or membership state | Three native Raft replicas with a test transport exercise follower quarantine and verify the remaining quorum commits the block. |
| Snapshot and eviction | Verify signed history before restoring membership or writing catch-up blocks | Bounded application path. |
| Participation follower | Verify genesis and each config before raw append or verifier updates | Focused append test observes ledger and verifier effects. Promotion uses the native startup barrier. |

The Linux restart harness interrupts a subprocess after persisting the Raft
commit but before the guard, after authorization but before native apply,
and after the native append but before checkpoint publication. It reopens
the same WAL and file ledger, checks repeated quarantine or authorized
recovery, and verifies the recovered Fabric block metadata and signature.
The subprocess runs the native Raft chain with a test support adapter.
CI records that test executable and the separately built orderer binary.

The dedicated PQ4.0D job records the tested revision, binaries, Linux runner,
Go version, and test output. See the PR checks for executed results, including
PQ4.0C, PQ4 components, Fabric unit and integration tests, and both PQ3 isolated
profiles. Endpoint-level enforcement, a distributed crash matrix, and
full shared TLS callback and resource publication remain open evidence.
