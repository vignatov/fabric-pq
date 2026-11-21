# PQ4.0 threat model: review draft

## Assets and scope

Protect confidentiality and integrity of session traffic and authenticate
the intended TLS endpoints on every required path in the
[coverage matrix](transport-coverage.md), including CCAAS and administration.
Preserve transaction signatures, channel validation, endorsement policy,
ledger integrity and the separation between enrollment and transport keys.
Current baseline transport is not PQ4 protected.

Assume an active network attacker can inspect, replay, delay, drop, inject or
redirect traffic and attempt TLS version, KEM, identity, hostname, endpoint
or policy downgrade. A passive attacker may retain captured encrypted
traffic for later cryptanalysis. TLS 1.3 hybrid key establishment and
ML-DSA authentication address different portions of that threat.

## Trust and policy questions requiring proof

- A TLS peer must verify its intended hostname, normal certificate path,
  validity and applicable usage before additional algorithm checks.
  Required mTLS paths must verify both endpoints. TLS credentials must be
  freshly generated and separate from enrollment keys.
- TLS starts before channel identification; bootstrap policy and its
  authenticated trust anchor must exist before network connections. Channel
  configuration alone cannot prevent a pre-channel fallback.
- A signed or authenticated node policy must not be silently replaced by
  an older or contradictory policy. The trusted administrator, policy
  distribution, rollback-resistant state and boot assumptions remain
  unselected and unproved.
- A shared listener must not allow a weaker channel or client to downgrade a
  strict channel. Administration and CCAAS cannot be left outside policy
  merely because they lack channel context.
- Unsupported or older software, missing policy, stale trust, changed
  certificates, reused connections and configuration reloads must not
  produce a silently weaker accepted connection. Prove these cases with
  cause-specific tests.
- Disable or explicitly restrict session resumption until its security
  properties are established. A resumed TLS 1.3 session is not evidence of a
  fresh ML-KEM exchange. Do not introduce 0-RTT.

## Limits

An attacker who controls a node's process, private keys or trusted local
configuration can generally bypass local enforcement; the eventual design
must state its operational trust and rollback assumptions instead of claiming
protection against arbitrary host compromise. Denial of service, traffic
analysis, trusted time, certificate revocation, external interoperability,
and third-party assessment remain production gates. A passing transport
handshake does not establish transaction validity; a committed transaction
does not establish the security of all its network paths.

In a [local baseline test](validation-and-evidence.md#live-baseline-configuration-and-rollback-experiment),
a single orderer served an older channel configuration after its ledger and
Raft state were restored, despite rejecting a stale signed update against the
newer state. This does not model an independently protected freshness source
or a multi-orderer cluster.

No certificate private keys, TLS secrets, session tickets or reusable
credentials may be included in CI evidence. The demo remains isolated,
development-only and subject to existing release guards.
