# PQ4.0 feasibility evidence

Status: **partial PQ4.0; the network-policy gate is not passed**.
The source baseline is `b10ce3a47dc62c6aee4d2de92e7bf70d7ba86012`.
PR #7 merged to `main`. The merged-commit
[PQ3 Isolated Network workflow](https://github.com/vignatov/fabric-pq/actions/runs/44952922129)
passed both temporary and permanent profile acceptance and protected-evidence
checks. The earlier local results in
[PQ3.5 validation](../pq2/development-and-validation.md#pq35-dual-profile-acceptance-results)
are associated with a dirty pre-merge tree, not the merged commit.

The later [PQ4.0B gate report](pq4.0b-gate-report.md) records a strict
`comm` component test and its remaining integration and lifecycle gaps. It
does not replace the baseline evidence below or establish a network-wide
transport policy.

## Local test environment and exact command

The feasibility tests ran with Go 1.27.4, `linux/amd64`, WSL Ubuntu 24.04,
`GOTOOLCHAIN=auto`, `GOFIPS140=off`, and an empty `GODEBUG`. They used fresh
test keys, loopback listeners and the repository's vendored dependencies.
The administration component test writes its short-lived credentials with
owner-only permissions under the Go test temporary directory, removed after
the test. The CCAAS shim component test sends its ephemeral server key to a
local child process over a pipe. No TLS key logging or uploaded private
credentials were used.

```text
GOFLAGS=-buildvcs=false go test -mod=vendor -race -count=1 github.com/hyperledger/fabric/integration/pq4/feasibility
PASS
GOFLAGS=-buildvcs=false go vet -mod=vendor github.com/hyperledger/fabric/integration/pq4/feasibility
PASS
GOFLAGS=-buildvcs=false go test -mod=vendor -trimpath -run TestFabricMSPMLDSATrustAnchor -count=1 github.com/hyperledger/fabric/integration/pq4/feasibility
PASS
GOFLAGS=-buildvcs=false go test -mod=vendor -race -count=5 -run TestFabricCCAASShimMLDSACompatibility github.com/hyperledger/fabric/integration/pq4/feasibility
PASS
GOFLAGS=-buildvcs=false go test -mod=vendor -race -count=5 -run TestFabricCCAASPlaintextMetadata github.com/hyperledger/fabric/integration/pq4/feasibility
PASS
GOFLAGS=-buildvcs=false go test -mod=vendor -race -count=5 -run TestAuthenticatedPolicyPrototype github.com/hyperledger/fabric/integration/pq4/feasibility
PASS
GOFLAGS=-buildvcs=false go test -mod=vendor -race -count=5 -run TestFabricCCAASPlaintextMetadata github.com/hyperledger/fabric/integration/pq4/feasibility
PASS
GOFLAGS=-buildvcs=false go test -mod=vendor -race -count=5 -run TestFabricAdminMLDSACompatibility github.com/hyperledger/fabric/integration/pq4/feasibility
PASS
```

The tests were run on a PQ4 feasibility worktree based on the commit above.
This result is not a clean-checkout peer/orderer network, release, or
production acceptance result.

## Unknown-capability compatibility experiment

The test-only name `PactwayPQ4FeasibilityUnknownCapability` is deliberately
unknown to the binaries; it is not an implemented or approved PQ4 capability.
The test creates a channel genesis containing that name and checks the
capability-specific rejection from actual peer and orderer processes. The
baseline binaries were built from this PQ4 worktree, whose production source
is based on `b10ce3a47dc62c6aee4d2de92e7bf70d7ba86012`.

The upstream binaries were built locally from Git commit
`986a09bb9ea6e06c0aad46d92e979c38029cbb1e` with its vendored dependencies;
their reported Go version was 1.27.3. The peer SHA-256 was
`0fdf9ed52879991bc232d068b69387e0bb5079dd9e4863a75da050e05b35cd34`
and the orderer SHA-256 was
`c61bda30313eb9dafc433cfc77b816a183b3003b52e30b1e6ee4ce47616ee25a`.
Both reported a development build. The hashes identify these particular
local builds, not a separately authenticated upstream release.

The source archive was extracted with
`git archive 986a09bb9ea6e06c0aad46d92e979c38029cbb1e | tar -x -C /tmp/pq4-upstream-18693a83-a606-4870-8d42-ca152170eac2`,
and the two binaries were built there with
`go build -mod=vendor -buildvcs=false -o peer ./cmd/peer` and
`go build -mod=vendor -buildvcs=false -o pq4-upstream-orderer ./cmd/orderer`.
The parent test used Go 1.27.4 and the following command; the temporary
directory is not retained:

```text
GOFLAGS=-buildvcs=false PACTWAY_UPSTREAM_PEER=/tmp/pq4-upstream-18693a83-a606-4870-8d42-ca152170eac2/peer PACTWAY_UPSTREAM_ORDERER=/tmp/pq4-upstream-18693a83-a606-4870-8d42-ca152170eac2/pq4-upstream-orderer PACTWAY_UPSTREAM_PEER_SHA256=0fdf9ed52879991bc232d068b69387e0bb5079dd9e4863a75da050e05b35cd34 PACTWAY_UPSTREAM_ORDERER_SHA256=c61bda30313eb9dafc433cfc77b816a183b3003b52e30b1e6ee4ce47616ee25a PACTWAY_UPSTREAM_PEER_REVISION=986a09bb9ea6e06c0aad46d92e979c38029cbb1e PACTWAY_UPSTREAM_ORDERER_REVISION=986a09bb9ea6e06c0aad46d92e979c38029cbb1e go test -mod=vendor -count=1 -timeout 15m -v -run TestMSP github.com/hyperledger/fabric/integration/msp -args -ginkgo.focus=PQ4
PASS: 3 selected specs; 11 unrelated specs filtered out
```

Both the baseline and pinned-upstream peer and orderer rejected the genesis
with the explicit "required but not supported" capability diagnostic. This
experiment does not demonstrate a PQ4 policy, prevent an old binary from
making a classical connection before channel identification, or show that a
future PQ4-required channel enforces transport security.

## Live baseline configuration and rollback experiment

On the PQ4 feasibility worktree at `5efd19928` plus this test and
documentation edits, the following focused test used a fresh local
single-orderer, two-organization Fabric network with baseline ECDSA TLS
credentials; its negotiated key-exchange groups were not observed:

```text
GOFLAGS=-buildvcs=false go test -mod=vendor -count=1 -timeout 15m -v -run TestMSP github.com/hyperledger/fabric/integration/msp -args -ginkgo.focus=PQ4.config.update.feasibility
PASS: 1 selected spec; 14 unrelated specs filtered out
```

An ordinary user could not authorize a channel configuration change. The two
organization admins and orderer admin then authorized removal of `V2_0`
while `V3_0` remained enabled, and the orderer committed the updated config.
This redundant-capability removal demonstrates generic capability
mutability, not an actual weakening of transport security. Replaying the
same signed update against the advanced config was rejected with the
capability value's version-conflict diagnostic.

After both peers were stopped, the test replaced the stopped orderer's
FileLedger and Raft state with the task-owned snapshot taken before the
update. On restart the single orderer served the earlier configuration
again and accepted the same signed update that had been rejected as stale
before the restore. This is an isolated local-state rollback, not a PQ4
network or a multi-orderer consensus test; it does not demonstrate how an
independent honest peer or protected checkpoint would respond. The test
removes its own temporary network and snapshots afterward.

## Baseline Raft quorum rollback experiment

A separate test used three baseline orderers, two peer organizations and
ECDSA TLS. It stopped a non-leader orderer and copied its FileLedger and Raft
state, then restarted it and committed the same redundant capability removal.
After confirming all three orderers served the updated config, it stopped that
orderer again, restored its earlier state and restarted it while the other
two orderers remained running. On the worktree based on `5e738e9bf`, the
following command was run three times:

```text
GOFLAGS=-buildvcs=false go test -mod=vendor -count=1 -timeout 15m -v -run TestMSP github.com/hyperledger/fabric/integration/msp -args -ginkgo.focus=characterizes.a.restored.orderer -ginkgo.v
PASS in 3 separate runs: 1 selected spec each; the restored orderer exited with a Raft commit-index panic each time
GOFLAGS=-buildvcs=false go vet -mod=vendor github.com/hyperledger/fabric/integration/msp
PASS
GOFLAGS=-buildvcs=false go test -mod=vendor -count=1 -timeout 15m -v -run TestMSP github.com/hyperledger/fabric/integration/msp -args -ginkgo.focus=PQ4.config.update.feasibility
PASS: 2 selected specs; 14 unrelated specs filtered out
```

In all three runs the restored orderer panicked with `tocommit(5) is out of
range [lastIndex(4)]` rather than catching up. The surviving orderers still
served the advanced configuration. A prior test run expecting catch-up failed
on the same panic; the revised test reports and verifies this outcome rather
than treating it as successful recovery. The test removes its own temporary
network and snapshots.

The test distinguishes the observed commit-index panic from a successful
catch-up followed by stale-update rejection; other exits or a timeout fail
the test. This is not evidence that the restored orderer rejects old policy
during startup or before TLS handshakes. It does not cover a rolled-back
quorum, Byzantine orderers, a freshness authority for peers or CCAAS, or a
PQ4 transport policy.

In [CI run 44972948242](https://github.com/vignatov/fabric-pq/actions/runs/44972948242),
the restored orderer emitted the expected commit-index panic, but the test
timed out while polling for its exit or catch-up. An unbounded config fetch
could block the poll, and creating a fresh asynchronous exit channel on every
poll could miss the exit. The test now bounds each fetch with a cancellable
context and retains one exit channel; it still rejects an unexpected exit,
failed catch-up or overall timeout.

## Observed results

| Check | Result and evidence boundary |
| --- | --- |
| Native TLS 1.3 with hybrid KEM | PASS. Both sides report `ConnectionState.CurveID == X25519MLKEM768`, TLS 1.3, full handshake and verified chains. |
| Native ML-DSA-65 CA and server/client leaves | PASS. Fresh keys, RFC 9881 ML-DSA-65 public-key and certificate-signature OIDs with absent parameters, normal chain signature verification, PKCS#8 serialization and `tls.X509KeyPair` are exercised. |
| Server and mutual TLS authentication | PASS in standalone connections. Both TLS certificates restrict `SupportedSignatureAlgorithms` to `tls.MLDSA65`, so a completed non-resumed handshake has only that permitted CertificateVerify choice. Incompatible restrictions fail. This is a controlled compatibility experiment, not a general connection-state signature-scheme field or a packet capture. |
| gRPC | PASS. A real gRPC health request over mutual TLS observes version, group and verified chains at both endpoints. |
| Negotiation failures | PASS. TLS 1.2-only clients and servers, and classical-X25519-only clients and servers, are rejected with version or key-exchange diagnostics. |
| Certificate failures | PASS. Untrusted CA, wrong DNS name or IP SAN, expired leaf, wrong server/client EKU, invalid certificate signature, missing required client cert, untrusted client and mismatched private key are rejected. A valid IP SAN is accepted. The invalid signature check asserts the ML-DSA verification diagnostic, not just a generic connection failure. |
| Invalid TLS signatures | PASS. A test-only signer corrupts each endpoint's TLS 1.3 CertificateVerify signature separately. The other endpoint rejects it with the corresponding server/client invalid-signature diagnostic; the certificate chain itself remains valid. |
| Additional endpoint-key check | PASS for an isolated test-only `VerifyConnection` callback that runs after normal X.509 validation and rejects an ECDSA leaf on either side while accepting ML-DSA-65 peers. This is not a selected or deployed Fabric policy. |
| Existing Fabric `comm` interoperability | PASS for a gRPC health request using the actual `comm` server and client constructors with ML-DSA-65 mutual credentials. The observed default connection negotiated X25519MLKEM768. This is a component test, not a complete Fabric network. |
| Existing Fabric fallback | The same unmodified `comm` server **accepted** a TLS 1.3 client restricted to classical X25519; both endpoints reported X25519. This confirms baseline configuration is not strict PQ4 policy. |
| Fabric server-credential minimum (historical baseline observation) | On the earlier baseline implementation, a controlled TLS 1.3-minimum server config was lowered by `comm.NewServerTransportCredentials`, and a clone also negotiated TLS 1.2. The current opt-in component tests instead exercise original, cloned and direct-factory credentials; all retain TLS 1.3 and reject TLS 1.2 and classical-only key exchange. These remain `comm` component tests, not node startup evidence. |
| Fabric MSP TLS roots | PASS. A real verifying MSP initialized with a fresh ML-DSA-65 TLS CA and rejected a leaf substituted as a CA. Its enrollment fixture remained separate and classical; this is not a hybrid-channel integration test. |
| Raft certificate metadata | PASS. The actual Raft metadata validator accepted ML-DSA-65 client/server certificates under their CA and rejected a server certificate issued by a different CA. This does not start Raft or validate network traffic. |
| Administration HTTPS components | PASS. `fabhttp` and the real `osnadmin` HTTP client exchanged a request with ML-DSA-65 mTLS and observed X25519MLKEM768. A second X25519-only client was also **accepted** by the same baseline admin listener. The handler is a test fixture, not a running orderer. |
| TLS-enabled CCAAS shim | PASS. A real chaincode shim configured to require a client certificate accepted an ML-DSA mutual TLS registration stream with X25519MLKEM768 and also **accepted** an X25519-only client. The client observes its verified server chain and negotiated group after standard verification; this fixture does not exercise either PQ3 peer-to-CCAAS link. |
| Fabric CCAAS client components | PASS. The actual external-builder connection-info constructor and `extcc.ExternalChaincodeRuntime` received the expected chaincode registration and ID from the TLS-enabled shim using fresh ML-DSA client and server credentials. The normal client verifier reported a verified ML-DSA server chain. The test supplies connection metadata and client key in memory only; it does not package or distribute the key, observe this connection's negotiated group, or run a Fabric peer. |
| Fabric CCAAS plaintext metadata | A real external-builder `Instance` read test release-directory metadata and the real external-chaincode runtime registered with a test gRPC service over plaintext. The service observed no client authentication both with `client_auth_required` false and with it true while `tls_required` was false. No Fabric peer, installed package, metadata tampering or server-side shim was exercised. |
| Signed-policy prototype | PASS for an isolated signed bootstrap policy with an assumed trusted checkpoint and a sample channel-config hash; Fabric's `channelconfig.NewBundle` parses the sample, but no channel-update authentication is exercised. It rejects missing, modified, untrusted, stale, equivocated, conflicting and weakened inputs, then enforces a strict server handshake. Restoring both an older policy and its checkpoint is accepted, demonstrating the checkpoint's necessary trust assumption. This does not exercise Fabric policy integration or real rollback-resistant storage. |
| HTTPS policy witness prototype | PASS for a test-only local HTTPS file server with a separately stored current policy, TLS 1.3, X25519MLKEM768 and ML-DSA mutual credentials. A restored older node policy was rejected while the witness remained current, but was accepted when the witness was restored too. An untrusted server, missing client certificate and unavailable witness fail; the test explicitly supplies a missing checkpoint after the fetch fails, and bootstrap rejects it. The witness and node state share a host and process, and no authority update, independent storage protection, automatic fail-closed behavior or Fabric listener is exercised. |

The Go toolchain's `crypto/tls` selects only the ML-DSA-65 signature scheme
for an ML-DSA-65 key in TLS 1.3. The controlled whitelist test validates
that selection without extracting handshake secrets. `ConnectionState` does
not expose the selected CertificateVerify scheme in this toolchain, so the
whitelist experiment must not be presented as direct per-connection scheme
telemetry for an uninstrumented Fabric network.

## Not yet established

- Native end-to-end peer, orderer, multi-orderer Raft, admin, gossip, Gateway,
  discovery, event and CCAAS compatibility with strict credentials and policy.
- Authenticated bootstrap, channel/node policy binding, policy rollback
  protection, shared-listener behavior and unsupported-binary rejection.
- Strict mixed-mode, configuration-update, certificate rotation and restart
  tests; per-path handshake evidence bound to committed transactions.
- TLS session resumption and early-data behavior outside these tests, where
  server tickets are disabled and client session caching is not configured.
- Full acceptance, performance measurements, FIPS-module compatibility,
  external clients, or any production/certification claim.

The tests intentionally include a baseline classical fallback. They do not
change Fabric's transport behavior. See
[transport-policy enforcement](transport-policy-enforcement.md) for the
mandatory unresolved architecture gate.

## Revised PQ4.0 gate status

The current focused work is not sufficient for a pass recommendation.
Partial or expected evidence:

| Gate proof | Status |
| --- | --- |
| Strict listener: TLS 1.2 and X25519-only rejection | Prototype test passes in standalone TLS. |
| Classical-only endpoint authentication rejection | Prototype test passes for ECDSA leaves. |
| Approved hybrid KEM and ML-DSA mutual TLS | Prototype test passes. |
| Bootstrap policy verification before readiness | Prototype test passes, but no Fabric listener integration. |
| Missing, invalid or conflicting bootstrap fail closed | Prototype test passes. |
| Channel capability and local policy agreement | Sample channel binding passes; no Fabric channel update or capability implementation. |
| Unauthorized channel downgrade | Exact channel hash binding passes for changed config; production update enforcement remains absent. |
| Unsupported-binary capability rejection | Existing baseline/upstream unknown-capability evidence passes; not a real PQ4 capability. |
| Strict CCAAS no plaintext | The baseline metadata/runtime test demonstrates plaintext. A test-only plaintext guard rejects `tls_required=false` but does not check client authentication, ML-DSA identity or hybrid key exchange; it is not integrated into the peer runtime. |
| Strict administration | Baseline Fabric HTTP components and a test-only strict HTTPS listener exercise ML-DSA mTLS. The strict listener rejects classical-only key exchange, TLS 1.2 and a classical client identity; it is not a Fabric admin listener. |
| Complete host-state rollback boundary | Explicitly out of the isolated development threat model; witness restoration demonstrates the limitation only as research evidence. |

An independent or hardware freshness service is not required for this gate.
It is a production requirement only for a threat model that includes complete
host-state rollback.

The live unsupported-capability integration pass also ran after the revised
review:

```text
GOFLAGS=-buildvcs=false go test -mod=vendor -count=1 -timeout 15m -v -run TestMSP github.com/hyperledger/fabric/integration/msp -args -ginkgo.focus=PQ4
PASS: 4 specs passed, 12 skipped (including the selected upstream-binary
spec, which requires separately supplied binaries)
```

That result confirms baseline and test-unknown-capability behavior only. It
is not evidence for an implemented PQ4 capability or for pre-handshake
transport rejection.

The Verify Build workflow includes a dedicated PQ4.0 Feasibility job running
`go test -mod=vendor -race -count=1 ./integration/pq4/feasibility` and
`go vet -mod=vendor ./integration/pq4/feasibility` with `GOFIPS140=off`.
The job exercises the same development-only non-FIPS environment; its status
on the pull request is the CI result, not a production or gate approval.
