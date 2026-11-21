# PQ4.0 architecture: review draft

**Status: no approved PQ4 transport implementation.** This document describes
the current boundary and questions for the mandatory architecture gate; it
does not authorize PQ4.1.

## Existing and intended boundaries

The existing network uses PQ1 hybrid transaction signatures and the
`pactway-hybrid-certificate-v1` enrollment profile with authenticated channel
capability `PactwayHybridCertificatePactwayV1`. Its transport certificates
are separate ECDSA credentials. Preserve both the enrollment profile and its
capability unchanged.

The proposed development-only `pactway-pq-tls-v1` would separately require
TLS 1.3, X25519MLKEM768 key establishment and ML-DSA-65 endpoint
authentication. Hybrid KEM and endpoint authentication are distinct
properties; ML-DSA-only authentication is not dual classical/PQ
authentication. This profile does not yet exist.

The scope includes both clients/peers, peer-to-orderer broadcast and block
delivery, gossip, multi-orderer Raft, the orderer admin API, participating
Gateway/discovery/event connections and both peer-to-CCAAS links. The
[coverage inventory](transport-coverage.md) identifies current constructors,
credentials, trust, and unprotected or untested paths.

## Transport construction boundaries

- `internal/pkg/comm` is shared by many gRPC paths but is not universal.
  Gossip constructs peer credentials independently; delivery and Gateway
  create or copy client configurations; orderer Raft may use a shared or
  separate listener.
- The orderer admin API and `osnadmin` use separate HTTP TLS constructors.
  The external-chaincode server's vendored shim also has its own TLS
  constructor and does not expose a strict curve setting through its public
  `TLSProperties`.
- Existing CCAAS links are plaintext. A secure design must protect their
  client and server ends without putting private keys in distributable
  chaincode packages.
- A policy associated only with an authenticated channel is unavailable when
  a listener handles the initial TLS handshake; administration and CCAAS also
  need enforceable non-channel policy. Candidate trust and enforcement
  approaches are in [transport-policy enforcement](transport-policy-enforcement.md).

## Feasibility and compatibility

[Validation evidence](validation-and-evidence.md) shows that Go 1.27.4 can
perform controlled native ML-DSA-65 mutual TLS and hybrid key establishment,
including gRPC, and that Fabric's shared `comm` component can carry an
ML-DSA-authenticated request. It also shows that the baseline `comm` server
accepts a classical-only X25519 client. This is not a network-wide test.

| Component or software | Current evidence |
| --- | --- |
| Native Go TLS/X.509 and gRPC | Standalone feasibility passes in the recorded non-FIPS environment. |
| Fabric `comm` constructors | ML-DSA mutual TLS component test passes, but strict group enforcement is absent. |
| Existing PQ3.5 network | Merged-commit baseline acceptance passed with ECDSA TLS authentication; actual key-exchange groups were not recorded. |
| Peer, orderer, Raft, admin, CCAAS and Gateway with PQ4 policy | Not tested; no PQ4 mode exists. |
| Existing or upstream binaries against a PQ4-required channel | Not tested; no PQ4 channel requirement exists. PQ3.5 enrollment-capability rejection is not evidence of PQ4 transport enforcement. |

Use FIPS 203, FIPS 204, RFC 8446,
[RFC 10024](https://www.rfc-editor.org/rfc/rfc10024.html) and
[RFC 9881](https://www.rfc-editor.org/rfc/rfc9881.html). The
[ML-DSA TLS 1.3 specification](https://datatracker.ietf.org/doc/draft-ietf-tls-mldsa/)
was `draft-ietf-tls-mldsa-06`, submitted for publication, at this audit;
recheck its status and deployed codepoints before implementation.
Go's ML-DSA package reports that it is unavailable with Go Cryptographic
Module v1.0.0; the passing test used `GOFIPS140=off`.

## Gate

Architecture review must select and substantiate a trusted policy and
bootstrap design, resolve shared-listener behavior, demonstrate all mandatory
positive and negative policy tests and prove unsupported-binary behavior
before any PQ4.1 transport change. See the
[policy proof gaps](transport-policy-enforcement.md#feasibility-evidence-and-gaps)
and [threat model](threat-model.md). Existing local code and successful
component handshakes do not pass that gate.
