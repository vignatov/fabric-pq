# PQ4.0 architecture: review draft

**Status: PQ4.0 architecture review in progress; PQ4.1 is not authorized.**
The reviewed isolated-development threat model and enforcement design are
recorded here, but implementation approval still requires the focused proofs
listed in the gate below.

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
authentication. A focused `comm` component prototype now exercises this
profile by requiring an ML-DSA-65 endpoint leaf key while retaining ordinary
X.509 path and hostname verification. CA and intermediate signature
algorithms are not constrained by this profile proof and may be classical;
quantum-resistant PKI issuance and trust paths are not claimed. The prototype
is not integrated into peer or orderer startup.

## PQ4.0B selected transport contract

The selected channel-level capability is `PactwayPQTransportV1`, distinct
from the enrollment capability. It requires the `pactway-pq-tls-v1` transport
floor and may only be selected in a fresh channel genesis. A protected channel
must not remove the capability; non-weakening configuration updates remain
possible through separately authorized local checkpoint advancement. The
capability does not authenticate a connection before its channel is known.

In strict mode every protected server authenticates using ML-DSA-65. TLS 1.3
and X25519MLKEM768 are required on all protected connections. Existing
listener-specific client-certificate requirements are retained: general
peer and orderer listeners may use server-authenticated TLS, while CCAAS and
orderer administration require mutual TLS with ML-DSA-65 client endpoint
identities. Where a client certificate is authenticated, a classical-only
endpoint leaf is rejected. Normal X.509 path, hostname, validity and usage
checks remain mandatory, but CA and intermediate signature algorithms are
not restricted. Baseline mode and Fabric MSP authentication are unchanged.

These are selected semantics, not an implementation or evidence that the gate
has passed. The focused proof must still establish the lifecycle and transport
properties in [transport-policy enforcement](transport-policy-enforcement.md).
The observed update/append ordering and candidate recovery protocol are
recorded for review in the [configuration activation ADR](adr-config-activation.md);
no lifecycle design is approved yet.

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
| Fabric `comm` constructors | Opt-in strict component tests enforce TLS 1.3, X25519MLKEM768 and ML-DSA endpoint leaf keys; original, cloned and direct-factory server credentials preserve the TLS 1.3 minimum. The unselected baseline remains classical-compatible. Node startup does not select or load the policy. |
| MSP TLS CA and Raft metadata validation | Component tests accept ML-DSA-65 TLS material and reject selected invalid inputs; no ML-DSA consensus network is demonstrated. |
| `fabhttp` and `osnadmin` | ML-DSA mutual TLS component test passes; the unmodified admin listener also accepts classical-only key exchange. |
| CCAAS client and chaincode shim | With TLS enabled in a test fixture, real external-builder, peer runtime and shim components register using ML-DSA mutual TLS credentials. Independently, the shim accepts both hybrid and classical-only key exchange. The real metadata reader and runtime also accept plaintext even when metadata requests client authentication if TLS is disabled. The PQ3 CCAAS deployment remains plaintext. |
| Signed bootstrap-policy prototype | An isolated test exercises an authenticated policy, assumed trusted checkpoint and strict server handshake. A local HTTPS witness demonstrates the checkpoint assumption but shares the test host. Neither establishes independently protected state or integrates with Fabric. |
| Live baseline configuration rollback | A single orderer serves an older configuration after restoring its state. In a separate three-orderer experiment, a restored orderer panicked on a Raft log-index inconsistency in three runs. Neither experiment establishes a PQ4 policy or pre-handshake freshness. |
| Existing PQ3.5 network | Merged-commit baseline acceptance passed with ECDSA TLS authentication; actual key-exchange groups were not recorded. |
| Peer, orderer, Raft, admin, CCAAS and Gateway with PQ4 policy | Not tested; no PQ4 mode exists. |
| Existing or upstream binaries against a PQ4-required channel | Not tested; no PQ4 channel requirement exists. Both baseline and pinned-upstream binaries reject a deliberately unknown test capability, which does not prove PQ4 transport enforcement. |

Use FIPS 203, FIPS 204, RFC 8446,
[RFC 10024](https://www.rfc-editor.org/rfc/rfc10024.html) and
[RFC 9881](https://www.rfc-editor.org/rfc/rfc9881.html). The
[ML-DSA TLS 1.3 specification](https://datatracker.ietf.org/doc/draft-ietf-tls-mldsa/)
was `draft-ietf-tls-mldsa-06`, submitted for publication, at this audit;
recheck its status and deployed codepoints before implementation.
Go's ML-DSA package reports that it is unavailable with Go Cryptographic
Module v1.0.0; the passing test used `GOFIPS140=off`.

## Gate

For isolated PQ4.0 development, the selected baseline is trusted
operator-protected local state: approved binaries and protected bootstrap
configuration, trust anchors and policy checkpoints. Network attackers and
incompatible or compromised remote participants are in scope. Complete
privileged-host compromise or simultaneous rollback of every local file,
secret and checkpoint is excluded. This baseline does not detect complete
host-state rollback.

The proposed implementation is layered: a trusted bootstrap policy governs
pre-handshake listeners and outbound connections, an authenticated
versioned channel capability binds channels to that policy, and explicit
endpoint policies cover CCAAS and administration. Shared listeners serving
any PQ4-required channel must enforce the strict profile for every
connection; a mixed configuration must be rejected rather than configured
with separate listener bypasses in the initial demonstration.

Mandatory evidence is listed in
[transport-policy enforcement](transport-policy-enforcement.md) and
[validation and evidence](validation-and-evidence.md). Existing local code
and successful component handshakes do not pass the gate.

## PQ4 implementation map

PQ4.1 may only proceed after the PQ4.0 gate passes. The implementation map
is:

- **PQ4.1 bootstrap and shared transport policy:** add strict configuration
  validation and policy loading before `comm` or HTTP listeners become ready;
  preserve classical constructors and behavior when PQ4 is not selected.
- **PQ4.2 channel binding:** add a distinct versioned transport capability,
  authenticated channel/update checks, local-policy agreement and downgrade
  rejection.
- **PQ4.3 Fabric peer/orderer transport:** apply strict TLS 1.3, X25519MLKEM768
  and ML-DSA-65 policy to shared peer and orderer connections, preserving
  strongest-policy behavior on PQ4 listeners and covering reload and pools.
- **PQ4.4 CCAAS and administration:** reject plaintext CCAAS metadata,
  require strict peer-to-CCAAS and server/client certificates, and apply the
  policy to orderer admin, peer operations and osnadmin paths.
- **PQ4.5 validation and release guard:** run end-to-end acceptance,
  unsupported-binary checks, rotation/restart tests and signed evidence
  collection before release; keep CCAAS private keys out of packages.

## Revised gate recommendation

The revised architecture is a defensible isolated-development design: a
trusted bootstrap policy can reject missing or weakened configuration before
listener readiness, a versioned authenticated channel binding can reject
disagreement and exact configuration changes, strongest-policy shared
listeners can prevent a weak connection from reaching a PQ4-required listener,
and explicit CCAAS/admin policies can close non-channel paths. The
operator-protected checkpoint is adequate only within the stated development
threat model; complete host-state rollback remains explicitly excluded.

The evidence remains incomplete. Standalone strict TLS, signed policy,
channel hash binding, a plaintext-only CCAAS guard and a strict HTTPS test
listener do not prove real Fabric listener readiness, channel-update
authentication, CCAAS runtime enforcement or peer/orderer integration.
The CCAAS guard does not validate client authentication, ML-DSA identity or
hybrid key exchange; the actual PQ4 CCAAS enforcement point must validate
those properties. The unknown-capability process test
proves unsupported software rejection for an unknown test name, not for an
approved PQ4 capability. Therefore the gate recommendation is **STOP:
do not proceed to PQ4.1 implementation** until the remaining real
integration proofs are added or explicitly delegated to a later, separately
approved implementation phase. Independent freshness is not required for
this isolated-development stop.
