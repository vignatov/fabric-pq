# Isolated PQ3 Fabric Network

This is an isolated development demonstration, not a production or payment
network. It uses only the `rfc5612-test-only-v1` certificate profile and
classical TLS. It makes no claim of quantum-resistant transport, high
availability, or Byzantine fault tolerance.

Run the commands below from WSL/Linux on an access-controlled Linux filesystem.
The default runtime directory is under `$HOME/.local/share/pactway-pq3`; do not
redirect it to a Windows-mounted filesystem. Docker Desktop, Docker Compose v2,
GNU make, and Go 1.27.4 are required. The Docker network is internal and no
container ports are published to the host by default.

Set the development-only environment explicitly in the shell that runs the
network:

```bash
export PACTWAY_HYBRID_PROFILE=rfc5612-test-only-v1
export PACTWAY_ISOLATED_DEVELOPMENT=true
```

## Lifecycle

The complete acceptance sequence is available as one command:

```bash
integration/pq3/pq3.sh acceptance
```

It runs shell/tool and unit validation, the focused hybrid MSP network suite,
source-built deployment, channel activation, chaincode lifecycle, repeated
transaction verification, negative endorsement, and recovery. It exports a
sanitized report and whitelisted evidence under
`build/pq3/acceptance-evidence/` before removing only the generated run's
containers, volumes, and private material. The report records the commands,
results, candidate gate commit, stage sample counts, and known limitations.
Raw test logs, private credentials, ledger volumes, and transaction block
bytes are not included. Set `PACTWAY_UPSTREAM_PEER` to a verified upstream
peer binary to run the compatibility check rather than record it as skipped.

The individual lifecycle commands remain useful for interactive inspection:

```bash
integration/pq3/pq3.sh fresh
integration/pq3/pq3.sh health
integration/pq3/pq3.sh join
integration/pq3/pq3.sh deploy
integration/pq3/pq3.sh invoke
integration/pq3/pq3.sh verify
integration/pq3/pq3.sh negative-endorsement
integration/pq3/pq3.sh recovery
```

`fresh` builds the actual peer and orderer images from the current Pactway
source tree, records the source commit/tree digest and image IDs, generates
independent hybrid keys and genesis material, and starts the three services
with Fabric's channel participation mode. It refuses to replace an active run.
The explicit `join` command uses `osnadmin` to join the orderer from the
generated application-channel block, then joins both peers.

```bash
integration/pq3/pq3.sh stop
integration/pq3/pq3.sh start
integration/pq3/pq3.sh restart
integration/pq3/pq3.sh resume
integration/pq3/pq3.sh status
```

These commands preserve the generated credentials, channel configuration, and
ledger volumes. `reset` is separate and destructive: it removes only the
active PQ3 Compose project, that project's named volumes, and that run's
generated material.

```bash
integration/pq3/pq3.sh reset
```

## Topology and custody

- `Org1MSP` and `Org2MSP` each operate one peer; `OrdererOrgMSP` operates one
  Raft orderer.
- Each organization installs and approves its own CCAAS package and runs a
  separate chaincode-server process; neither peer shares the other
  organization's execution service.
- Peer and orderer images are locally built from this repository; Compose uses
  `pull_policy: never` and a private local image namespace.
- Node services receive only their own local MSP and TLS material. The CLI
  service receives only the selected organization’s client/admin MSPs.
- Runtime private keys, ledgers, temporary-profile artifacts, and evidence
  stay under the Linux runtime directory and are ignored by Git and Docker build
  contexts. Do not copy or publish that directory.
- The Compose network is internal. If a future presentation requires host
  access, any port publication must be loopback-only and separately reviewed.

The isolated workflow runs peer-level rejection checks for invalid-PQ-signature
and classical-only client proposals, expiry/replay acceptance, and classical-only
and stale orderer signer rejection. Its negative-validation packages also
exercise wrong MSP organizations and roles, unsupported certificate profiles,
and missing PQ keys. The live hybrid network acceptance test also attempts to
start an orderer with unsupported-profile, wrong-role, wrong-organization, and
missing-PQ-key identities; it submits an unauthorized application config update
and an authorized attempt to remove the required channel capability, asserting
the corresponding rejections.
It checks that the verified upstream Fabric v3.1.5 peer rejects a channel requiring the
fork-only hybrid capability. The workflow also checks channel activation,
organization-specific chaincode lifecycle, two-organization endorsement,
transaction-bound cryptographic and commit evidence, negative endorsement, and
state-preserving recovery. Starting three containers alone is not PQ3
completion. The upstream check demonstrates rejection of this unsupported
capability, not interoperability.

`deploy` installs a distinct external CCAAS package on each organization's peer,
approves the corresponding package IDs, commits sequence 1 with
`AND('Org1MSP.peer','Org2MSP.peer')`, and starts the two chaincode servers.
Each `invoke` run creates a unique asset key, submits an `InitAsset` transaction
followed by a state-changing `Set`, and checks the expected value on both
peers after each commit. It queries each peer's QSCC ledger for the exact
transaction and its committed block. `pq3-verify` requires the transaction's
validation code to be `VALID` in the block and both peer ledgers, compares the
exact committed envelope across them, verifies the orderer block signature and
the client/endorsement signatures, and checks that the endorsed write set and
both peer state reads match the expected key and value. The report is bound to
that transaction ID; it cannot succeed based on an unrelated newest block or
signatures alone. Repeated `invoke` runs use fresh asset keys and retain
transaction-specific reports.

`negative-endorsement` submits a write with only Org1's endorsement. The peer
reports `ENDORSEMENT_POLICY_FAILURE`; both peers' state remains unchanged, and
the verifier rejects the exact transaction based on its committed validation
code. `recovery` checks both peer memberships, the active orderer channel, and
the latest asset key/value after stop/start, restart, and resume.
The `PQ3 Isolated Network` workflow runs the single acceptance command on a
source-built, internal Docker network and uploads only the sanitized evidence
report and its whitelisted evidence files. It does not upload generated
credentials or private runtime artifacts.

The verifier output and fetched block are stored under the run's private
Linux-side evidence directory. They are demonstration evidence, not an
independent production audit or a claim that the classical TLS transport is
post-quantum secure. Locally observed successful transaction timings are
recorded per transaction and stage in `stage-timings.jsonl`, with UTC
start/end times and millisecond durations. The stages are proposal preparation,
endorsement collection, local broadcast submission/acknowledgment, and waiting
for commit delivery from all configured peers. This does not isolate orderer
consensus time, and these observations are neither signed protocol timestamps
nor performance guarantees. Sample counts and those limitations are reported
in `stage-timing-summary.json`. Coarse whole-second lifecycle durations remain
in `timings.txt`.

The demo has one Raft orderer and makes no availability or fault-tolerance
claim. It does not implement settlement tokens or PQ4; settlement integration
must remain a separate change and must not treat this demo's classical TLS as
post-quantum protection.
