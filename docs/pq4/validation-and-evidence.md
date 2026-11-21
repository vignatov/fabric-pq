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
`GOTOOLCHAIN=auto`, `GOFIPS140=off`, and an empty `GODEBUG`. They used fresh,
in-memory test keys, loopback listeners and the repository's vendored
dependencies. No TLS key logging or private credential artifacts were used.

```text
go test -mod=vendor -race -count=1 github.com/hyperledger/fabric/integration/pq4/feasibility
PASS
```

The tests were run on a PQ4 feasibility worktree based on the commit above.
This result is not a clean-checkout peer/orderer network, release, or
production acceptance result.

## Observed results

| Check | Result and evidence boundary |
| --- | --- |
| Native TLS 1.3 with hybrid KEM | PASS. Both sides report `ConnectionState.CurveID == X25519MLKEM768`, TLS 1.3, full handshake and verified chains. |
| Native ML-DSA-65 CA and server/client leaves | PASS. Fresh keys, RFC 9881 ML-DSA-65 public-key and certificate-signature OIDs with absent parameters, normal chain signature verification, PKCS#8 serialization and `tls.X509KeyPair` are exercised. |
| Server and mutual TLS authentication | PASS in standalone connections. Both TLS certificates restrict `SupportedSignatureAlgorithms` to `tls.MLDSA65`, so a completed non-resumed handshake has only that permitted CertificateVerify choice. Incompatible restrictions fail. This is a controlled compatibility experiment, not a general connection-state signature-scheme field or a packet capture. |
| gRPC | PASS. A real gRPC health request over mutual TLS observes version, group and verified chains at both endpoints. |
| Negotiation failures | PASS. TLS 1.2-only clients and servers, and classical-X25519-only clients and servers, are rejected with version or key-exchange diagnostics. |
| Certificate failures | PASS. Untrusted CA, wrong DNS name or IP SAN, expired leaf, wrong server/client EKU, invalid certificate signature, missing required client cert, untrusted client and mismatched private key are rejected. A valid IP SAN is accepted. The invalid signature check asserts the ML-DSA verification diagnostic, not just a generic connection failure. |
| Additional endpoint-key check | PASS for an isolated test-only `VerifyConnection` callback that runs after normal X.509 validation and rejects an ECDSA leaf on either side while accepting ML-DSA-65 peers. This is not a selected or deployed Fabric policy. |
| Existing Fabric `comm` interoperability | PASS for a gRPC health request using the actual `comm` server and client constructors with ML-DSA-65 mutual credentials. The observed default connection negotiated X25519MLKEM768. This is a component test, not a complete Fabric network. |
| Existing Fabric fallback | The same unmodified `comm` server **accepted** a TLS 1.3 client restricted to classical X25519; both endpoints reported X25519. This confirms baseline configuration is not strict PQ4 policy. |

The Go toolchain's `crypto/tls` selects only the ML-DSA-65 signature scheme
for an ML-DSA-65 key in TLS 1.3. The controlled whitelist test validates
that selection without extracting handshake secrets. `ConnectionState` does
not expose the selected CertificateVerify scheme in this toolchain, so the
whitelist experiment must not be presented as direct per-connection scheme
telemetry for an uninstrumented Fabric network.

## Not yet established

- Native end-to-end peer, orderer, multi-orderer Raft, admin, gossip, Gateway,
  discovery, event and CCAAS compatibility with strict credentials.
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
