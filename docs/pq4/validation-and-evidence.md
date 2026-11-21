# PQ4.0 feasibility evidence

Status: **partial PQ4.0; the network-policy gate is not passed**.
The source baseline is `b10ce3a47dc62c6aee4d2de92e7bf70d7ba86012`.
PR #7 merged to `main`. The merged-commit
[PQ3 Isolated Network workflow](https://github.com/vignatov/fabric-pq/actions/runs/44952922129)
passed both temporary and permanent profile acceptance and protected-evidence
checks. The earlier local results in
[PQ3.5 validation](../pq2/development-and-validation.md#pq35-dual-profile-acceptance-results)
are associated with a dirty pre-merge tree, not the merged commit.

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
| Fabric MSP TLS roots | PASS. A real verifying MSP initialized with a fresh ML-DSA-65 TLS CA and rejected a leaf substituted as a CA. Its enrollment fixture remained separate and classical; this is not a hybrid-channel integration test. |
| Raft certificate metadata | PASS. The actual Raft metadata validator accepted ML-DSA-65 client/server certificates under their CA and rejected a server certificate issued by a different CA. This does not start Raft or validate network traffic. |
| Administration HTTPS components | PASS. `fabhttp` and the real `osnadmin` HTTP client exchanged a request with ML-DSA-65 mTLS and observed X25519MLKEM768. A second X25519-only client was also **accepted** by the same baseline admin listener. The handler is a test fixture, not a running orderer. |
| TLS-enabled CCAAS shim | PASS. A real chaincode shim configured to require a client certificate accepted an ML-DSA mutual TLS registration stream with X25519MLKEM768 and also **accepted** an X25519-only client. The client observes its verified server chain and negotiated group after standard verification; this fixture does not exercise either PQ3 peer-to-CCAAS link. |

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
