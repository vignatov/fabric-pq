# PQ4.0 transport inventory

Status: **baseline audit, not a PQ4 security claim**. The baseline is
`b10ce3a47dc62c6aee4d2de92e7bf70d7ba86012`; the existing network uses
ECDSA TLS certificates, and no PQ4 transport policy exists. Go's defaults
may negotiate hybrid key exchange on some links; no baseline network
handshake evidence establishes which group was used.

The revised PQ4.0 design requires strict policy at bootstrap and on every
protected listener and endpoint. Any listener serving a PQ4-required channel
must enforce the strict listener profile for all connections. In strict
mode, CCAAS `tls_required=false` is invalid regardless of
`client_auth_required`.

The new scope requires CCAAS as well as administration. "Required" below
means a future PQ4 acceptance obligation, not that the baseline satisfies it.
Unless noted, endpoint values are from
[PQ3 Compose](../../integration/pq3/compose.yaml) and
[its workflow](../../integration/pq3/pq3.sh). The peer and general orderer
listeners use [comm](../../internal/pkg/comm/server.go), whose server
credentials permit TLS 1.2 and TLS 1.3; its clients also permit TLS 1.2.
Normal Go hostname verification applies unless the caller sets a hostname
override. The baseline peer and general orderer settings do not require
client TLS certificates. Transport and enrollment credentials are distinct.

| Path and PQ4 scope | Baseline endpoints, construction, credentials and trust | Baseline status and missing proof |
| --- | --- | --- |
| Org1 and Org2 clients to either peer: required | CLI clients use `comm.ClientConfig` via [peerclient.go](../../internal/peer/common/peerclient.go) and [common.go](../../internal/peer/common/common.go); peers serve `peer0.org1.pactway.local:7051` and `peer0.org2.pactway.local:8051`. Each peer loads its own generated TLS server key/cert; CLI supplies the target org's TLS CA. The demo does not configure peer mTLS. | TLS with ECDSA server authentication; TLS 1.3 is supported but the negotiated group is unrecorded. Both orgs and cross-org endorsement connections need actual PQ4 evidence. |
| CLI to orderer broadcast and lifecycle operations: required | [ordererclient.go](../../internal/peer/common/ordererclient.go) uses `comm.ClientConfig` to connect to `orderer0.ordererorg.pactway.local:7050`; the CLI supplies OrdererOrg's TLS CA and the orderer loads its TLS server cert/key. General TLS client authentication is off in the baseline. | ECDSA server authentication; TLS 1.3 supported, group unobserved. Requires strict client and listener policy. |
| Peer to orderer for block delivery: required | The peer initiates the TLS connection to the orderer's general listener; blocks flow back from orderer to peer on that stream. [deliveryclient.go](../../core/deliverservice/deliveryclient.go), [config.go](../../core/deliverservice/config.go) and [adapters.go](../../common/deliverclient/blocksprovider/adapters.go) copy `comm.ClientConfig` and add channel-derived orderer TLS roots; peer client certs are loaded when client authentication is configured. | Baseline orderer server authentication is ECDSA; general listener does not require mTLS. TLS 1.3 is supported; group unobserved. Do not describe the data direction as a separate orderer-initiated handshake. |
| Peer to peer gossip: required | Peers' shared gRPC listeners use their node TLS credentials. [secureDialOpts](../../internal/peer/node/start.go) obtains `CredentialSupport.GetPeerCredentials`; [connection.go](../../internal/pkg/comm/connection.go) combines configured and channel-derived peer TLS roots and holds a client certificate. | TLS is enabled in Compose but inbound peer mTLS is off. TLS 1.3 is supported, group unobserved. Test real gossip in both directions and policy preservation across root/cert updates. |
| Gateway to remote endorser/orderer: required when used | Gateway is registered on the peer listener. [endpoint.go](../../internal/pkg/gateway/endpoint.go) constructs new `comm.ClientConfig` objects using discovered endpoint roots and the configured client certificate/key. Client TLS is enabled based on the presence of roots. | Current endpoint factory can select plaintext when roots are absent; inspect actual demonstration traffic and reject missing roots in strict mode. TLS 1.3 is supported when TLS is enabled; no negotiated evidence exists. |
| Gateway, discovery and event/deliver clients to peers: required when used | The services are registered on the same peer gRPC server in [start.go](../../internal/peer/node/start.go). A client's TLS constructor and CA depend on the client/tool; peer identity and optional mTLS match the first row. | The existing CLI workflow is not evidence that every Gateway/discovery/event API path was exercised. Identify participating clients and verify their actual connections in PQ4. |
| Orderer to orderer Raft: required | [orderer server setup](../../orderer/common/server/main.go) creates the cluster dialer and either reuses the general listener or creates a separate `comm` listener. It loads cluster client/server certs and configured TLS roots; the separate listener requires verified client certs, and cluster identity checks are additional to TLS. | The baseline has one orderer: no inter-orderer connection is demonstrated. Go TLS 1.3 is available, but neither a Raft handshake nor its group/authentication has been observed. Test multiple orderers and both listener configurations where supported. |
| `osnadmin` to orderer admin API: required | `cli-orderer-admin` connects to `orderer0:9443`. [osnadmin](../../cmd/osnadmin/main.go) loads OrdererOrg's CA and node client cert/key; [HTTP client](../../internal/osnadmin/httpclient.go) creates its own `tls.Config`. [fabhttp](../../common/fabhttp/tls.go) loads the orderer server cert/key and client-root CA. Compose requires mTLS. | Separate HTTP TLS constructors permit/default to TLS 1.2 and TLS 1.3. ECDSA authentication; actual group unobserved. Cannot be covered by changing `comm` alone. |
| Org1 and Org2 peers to their own CCAAS servers: **required** | [externalbuilder](../../core/container/externalbuilder/instance.go) reads `connection.json` and builds `comm.ClientConfig`; [extcc](../../core/chaincode/extcc/extcc_handler.go) dials the chaincode server. The baseline package sets `tls_required: false`; [chaincode server](../../integration/pq3/chaincode_server.go) sets `Disabled: true`. | **Plaintext**, not a local loopback link: the services communicate over the internal Compose network. A component test confirms the actual external-builder metadata reader and runtime register over plaintext even if `client_auth_required` is true while `tls_required` is false. No certificate, trust anchor or mTLS exists on these links. A separately TLS-enabled shim fixture accepts both hybrid and classical-only connections; its TLS loader sets a TLS 1.2 minimum and `TLSProperties` exposes no strict group setting. Secure both links and independently prove server-side enforcement. |
| Other chaincode-to-peer listener: separate from CCAAS | [peer startup](../../internal/peer/node/start.go) creates a separate `comm` chaincode listener. With peer TLS enabled it creates a self-signed chaincode CA, server certificate and required client certificate authentication. | Not the peer-initiated CCAAS connection above. Determine actual use in the PQ4 demo and explicitly classify it; do not assume the enrollment TLS CA or CCAAS TLS policy governs this separate listener. |
| Peer/orderer operations APIs: local-only baseline; outside the stated transaction-path claim unless explicitly added | [peer sample](../../sampleconfig/core.yaml) binds operations to `127.0.0.1:9443`; [orderer sample](../../sampleconfig/orderer.yaml) uses `127.0.0.1:8443`. TLS is disabled by default; Compose does not publish ports. | Local process/container exposure is not post-quantum protection. Reassess if bindings, container access or usage change; no TLS/mTLS/group is present in the default configuration. |
| Compose health probes: local-only; excluded from transaction-security claim | Container health checks open local TCP connections to the peer/orderer/CCAAS listeners; they do not complete TLS or send transaction payloads. | Not evidence of endpoint authentication or a protected application connection. |

## Cross-cutting gaps

- [Server credentials](../../internal/pkg/comm/creds.go) explicitly set the
  server minimum to TLS 1.2, including on credential clones. A
  [component test](validation-and-evidence.md#observed-results) confirms
  actual TLS 1.2 negotiation after each reset.
  [Dynamic credentials](../../internal/pkg/comm/creds.go),
  [connection management](../../orderer/common/cluster/connectionsmgr.go),
  delivery and Gateway factories must preserve any future policy and reject
  incompatible cached connections.
- [Certificate generation](../../cmd/pactway-pq-gen/main.go) creates fresh
  per-organization ECDSA TLS authorities and separate server/client leaves;
  enrollment identity and TLS keys are not interchangeable. CCAAS
  `connection.json` can contain a PEM client private key, so blindly placing
  it into distributed chaincode packages would leak credentials.
- TLS 1.3 capability in a constructor is not proof of hybrid negotiation,
  ML-DSA authentication, trust-chain validation or mTLS. Every required
  connection needs an observed, transaction-relevant acceptance record.
- This is a source inventory, not a complete runtime trace. Resolve remaining
  actual-use, external-client, credential-rotation and endpoint-binding
  questions before the architecture gate can pass.
