#!/usr/bin/env bash

# Copyright the Hyperledger Fabric contributors. All rights reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#

set -euo pipefail

readonly PROFILE="rfc5612-test-only-v1"
readonly CHANNEL_ID="pactway-pq3-demo"
readonly FABRIC_VERSION="3.1.5"
readonly GO_VERSION="1.27.4"
readonly DOCKER_NAMESPACE="localhost/pactway-pq3"
readonly CHAINCODE_NAME="pq3asset"
readonly CHAINCODE_VERSION="1.0"
readonly CHAINCODE_SEQUENCE="1"
readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)"
readonly DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}"
readonly STATE_ROOT="${PQ3_STATE_ROOT:-$DATA_HOME/pactway-pq3}"
readonly REPO_KEY="$(printf '%s' "$ROOT" | sha256sum | cut -c1-12)"
readonly STATE_DIR="$STATE_ROOT/$REPO_KEY"
readonly ACTIVE_FILE="$STATE_DIR/active-run"

CHAINCODE_ID_ORG1=""
CHAINCODE_ID_ORG2=""
CURRENT_STATE_KEY=""
CURRENT_STATE_VALUE=""
ACCEPTANCE_OUTPUT_DIR=""
ACCEPTANCE_LOG_DIR=""
ACCEPTANCE_STATE_ROOT=""
ACCEPTANCE_CURRENT_STEP=""
ACCEPTANCE_RUN_ID=""
ACCEPTANCE_STEPS=()

fail() {
	printf 'pq3: %s\n' "$*" >&2
	exit 1
}

record_duration() {
	local name="$1" started="$2"
	printf '%s_seconds=%d\n' "$name" "$((SECONDS - started))" \
		>> "$RUN_DIR/evidence/timings.txt"
}

require_isolated_profile() {
	[[ "${PACTWAY_HYBRID_PROFILE:-}" == "$PROFILE" ]] ||
		fail "set PACTWAY_HYBRID_PROFILE=$PROFILE explicitly"
	[[ "${PACTWAY_ISOLATED_DEVELOPMENT:-}" == "true" ]] ||
		fail "set PACTWAY_ISOLATED_DEVELOPMENT=true explicitly"
}

check_prerequisites() {
	command -v go >/dev/null || fail "Go $GO_VERSION is required"
	command -v make >/dev/null || fail "GNU make is required"
	command -v docker >/dev/null || fail "Docker CLI is required"
	[[ "$(go env GOVERSION)" == "go$GO_VERSION" ]] ||
		fail "Go $GO_VERSION is required; found $(go env GOVERSION)"
	docker info >/dev/null 2>&1 || fail "Docker Desktop is not ready"
	docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 is required"
}

check_linux_data_filesystem() {
	mkdir -p -- "$STATE_DIR"
	local filesystem
	filesystem="$(stat -f -c '%T' "$STATE_DIR")"
	case "$filesystem" in
		9p|drvfs|ntfs3|cifs)
			fail "private material must be stored on the WSL/Linux filesystem, not $filesystem"
			;;
	esac
}

source_tree_digest() {
	git -C "$ROOT" ls-files -co --exclude-standard -z |
		sort -z |
		xargs -0 -r sha256sum |
		sha256sum |
		cut -d ' ' -f 1
}

build_runtime_images() {
	local source_commit tree_digest revision_tag source_dirty
	source_commit="$(git -C "$ROOT" rev-parse HEAD)"
	tree_digest="$(source_tree_digest)"
	revision_tag="pq3-${source_commit:0:7}-${tree_digest:0:12}"
	if [[ -n "$(git -C "$ROOT" status --porcelain --untracked-files=all)" ]]; then
		source_dirty=true
	else
		source_dirty=false
	fi

	make -C "$ROOT" peer-docker orderer-docker \
		DOCKER_NS="$DOCKER_NAMESPACE" \
		UBUNTU_VER=24.04 \
		FABRIC_VER="$FABRIC_VERSION" \
		GO_VER="$GO_VERSION" \
		EXTRA_VERSION="$revision_tag"

	IMAGE_TAG="$FABRIC_VERSION-snapshot-$revision_tag"
	docker image tag "$DOCKER_NAMESPACE/fabric-peer:$FABRIC_VERSION" \
		"$DOCKER_NAMESPACE/fabric-peer:$IMAGE_TAG"
	docker image tag "$DOCKER_NAMESPACE/fabric-orderer:$FABRIC_VERSION" \
		"$DOCKER_NAMESPACE/fabric-orderer:$IMAGE_TAG"

	mkdir -p -- "$ROOT/build/pq3"
	go -C "$ROOT" build -mod=vendor -trimpath -buildvcs=false \
		-o "$ROOT/build/pq3/chaincode" ./integration/pq3
	go -C "$ROOT" build -mod=vendor -trimpath -buildvcs=false \
		-o "$ROOT/build/pq3/osnadmin" ./cmd/osnadmin
	go -C "$ROOT" build -mod=vendor -trimpath -buildvcs=false \
		-o "$ROOT/build/pq3/pq3-verify" ./cmd/pq3-verify
	mkdir -p -- "$RUN_DIR/ccaas"
	cp -- "$ROOT/build/pq3/chaincode" "$RUN_DIR/ccaas/chaincode"
	mkdir -p -- "$RUN_DIR/tools"
	cp -- "$ROOT/build/pq3/osnadmin" "$RUN_DIR/tools/osnadmin"
	cp -- "$ROOT/build/pq3/pq3-verify" "$RUN_DIR/tools/pq3-verify"

	CC_IMAGE="$DOCKER_NAMESPACE/ccaas:$IMAGE_TAG"
	TOOLS_IMAGE="$DOCKER_NAMESPACE/tools:$IMAGE_TAG"
	PEER_IMAGE="$DOCKER_NAMESPACE/fabric-peer:$IMAGE_TAG"
	ORDERER_IMAGE="$DOCKER_NAMESPACE/fabric-orderer:$IMAGE_TAG"
	docker build --pull \
		--file "$SCRIPT_DIR/ccaas.Dockerfile" \
		--tag "$CC_IMAGE" \
		"$RUN_DIR/ccaas"
	build_tools_image

	printf '%s\n' "$IMAGE_TAG" > "$RUN_DIR/image-tag"
	printf '%s\n' "$source_commit" > "$RUN_DIR/source-commit"
	printf '%s\n' "$tree_digest" > "$RUN_DIR/source-tree-sha256"
	printf '%s\n' "$source_dirty" > "$RUN_DIR/source-dirty"
	printf '%s\n' "$CC_IMAGE" > "$RUN_DIR/ccaas-image"
	printf '%s\n' "$TOOLS_IMAGE" > "$RUN_DIR/tools-image"

	local peer_image_id orderer_image_id ccaas_image_id tools_image_id
	peer_image_id="$(docker image inspect --format '{{.Id}}' "$PEER_IMAGE")"
	orderer_image_id="$(docker image inspect --format '{{.Id}}' "$ORDERER_IMAGE")"
	ccaas_image_id="$(docker image inspect --format '{{.Id}}' "$CC_IMAGE")"
	tools_image_id="$(docker image inspect --format '{{.Id}}' "$TOOLS_IMAGE")"
	mkdir -p -- "$RUN_DIR/evidence"
	cat > "$RUN_DIR/evidence/network-manifest.json" <<EOF
{
  "source_commit": "$source_commit",
  "source_tree_sha256": "$tree_digest",
  "source_worktree_dirty": $source_dirty,
  "fabric_version": "$FABRIC_VERSION",
  "go_version": "$GO_VERSION",
  "hybrid_profile": "$PROFILE",
  "isolated_development": true,
  "channel_id": "$CHANNEL_ID",
  "channel_capability": "PactwayHybridCertificateV1",
  "tls_transport": "classical TLS",
  "docker_network_internal": true,
  "host_ports_published": false,
  "peer_image": "$PEER_IMAGE",
  "peer_image_id": "$peer_image_id",
  "orderer_image": "$ORDERER_IMAGE",
  "orderer_image_id": "$orderer_image_id",
  "chaincode_execution_service_count": 2,
  "chaincode_image": "$CC_IMAGE",
  "chaincode_image_id": "$ccaas_image_id",
  "admin_tools_image": "$TOOLS_IMAGE",
  "admin_tools_image_id": "$tools_image_id",
  "compose_sha256": "$(sha256sum "$SCRIPT_DIR/compose.yaml" | cut -d ' ' -f 1)",
  "orderer_config_sha256": "$(sha256sum "$ROOT/sampleconfig/orderer.yaml" | cut -d ' ' -f 1)"
}
EOF
}

build_tools_image() {
	docker build --pull \
		--file "$SCRIPT_DIR/tools.Dockerfile" \
		--tag "$TOOLS_IMAGE" \
		"$RUN_DIR/tools"
}

load_active() {
	[[ -f "$ACTIVE_FILE" ]] || fail "no active PQ3 run; use fresh first"
	local run_id
	run_id="$(<"$ACTIVE_FILE")"
	[[ "$run_id" =~ ^run-[0-9]+-[0-9]+-[0-9]+$ ]] ||
		fail "invalid active run identifier"
	RUN_ID="$run_id"
	RUN_DIR="$STATE_DIR/$RUN_ID"
	[[ -d "$RUN_DIR" && -f "$RUN_DIR/.pq3-run" ]] ||
		fail "active run directory or marker is missing"
	PROJECT="pq3-$REPO_KEY-${RUN_ID#run-}"
	grep -Fxq "project=$PROJECT" "$RUN_DIR/.pq3-run" ||
		fail "active run marker does not match its project"

	if [[ -f "$RUN_DIR/image-tag" ]]; then
		IMAGE_TAG="$(<"$RUN_DIR/image-tag")"
		[[ "$IMAGE_TAG" =~ ^[A-Za-z0-9._-]+$ ]] || fail "invalid image tag in active run"
	else
		IMAGE_TAG=""
	fi
	[[ -f "$RUN_DIR/ccaas-image" ]] && CC_IMAGE="$(<"$RUN_DIR/ccaas-image")" || CC_IMAGE=""
	[[ -f "$RUN_DIR/chaincode-id-org1" ]] && CHAINCODE_ID_ORG1="$(<"$RUN_DIR/chaincode-id-org1")" || CHAINCODE_ID_ORG1=""
	[[ -f "$RUN_DIR/chaincode-id-org2" ]] && CHAINCODE_ID_ORG2="$(<"$RUN_DIR/chaincode-id-org2")" || CHAINCODE_ID_ORG2=""
	[[ -f "$RUN_DIR/current-state-key" ]] && CURRENT_STATE_KEY="$(<"$RUN_DIR/current-state-key")" || CURRENT_STATE_KEY=""
	[[ -f "$RUN_DIR/current-state-value" ]] && CURRENT_STATE_VALUE="$(<"$RUN_DIR/current-state-value")" || CURRENT_STATE_VALUE=""
	export PQ3_RUN_DIR="$RUN_DIR"
	export PQ3_MATERIAL_DIR="$RUN_DIR/material"
	export PQ3_IMAGE_TAG="$IMAGE_TAG"
	export PQ3_CHAINCODE_ID_ORG1="$CHAINCODE_ID_ORG1"
	export PQ3_CHAINCODE_ID_ORG2="$CHAINCODE_ID_ORG2"
	COMPOSE_FILE="$RUN_DIR/config/compose.yaml"
	if [[ -f "$COMPOSE_FILE" ]]; then
		PROJECT="$PROJECT" docker compose --profile cli --project-name "$PROJECT" \
			--file "$COMPOSE_FILE" config --quiet >/dev/null ||
			fail "active Compose configuration is invalid"
	fi
}

compose() {
	[[ -f "$COMPOSE_FILE" ]] || fail "run configuration is incomplete; reset this run"
	docker compose --profile cli --project-name "$PROJECT" --file "$COMPOSE_FILE" "$@"
}

run_cli() {
	local service="$1"
	local identity="$2"
	shift 2
	compose run --rm --no-deps -e "CORE_PEER_MSPCONFIGPATH=/run/msp/$identity" "$service" "$@"
}

run_timed_cli() {
	local service="$1"
	local identity="$2"
	shift 2
	compose run --rm --no-deps \
		-e "CORE_PEER_MSPCONFIGPATH=/run/msp/$identity" \
		-e PACTWAY_STAGE_TIMINGS=true \
		"$service" "$@"
}

wait_healthy() {
	local deadline=$((SECONDS + 180))
	local services=(orderer peer-org1 peer-org2)
	if [[ -n "$CHAINCODE_ID_ORG1" && -n "$CHAINCODE_ID_ORG2" ]]; then
		services+=(ccaas-org1 ccaas-org2)
	fi
	while (( SECONDS < deadline )); do
		local all_healthy=true service container_id status
		for service in "${services[@]}"; do
			container_id="$(compose ps -q "$service" 2>/dev/null || true)"
			if [[ -z "$container_id" ]]; then
				all_healthy=false
				break
			fi
			status="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$container_id" 2>/dev/null || true)"
			[[ "$status" == "healthy" ]] || { all_healthy=false; break; }
		done
		[[ "$all_healthy" == true ]] && return 0
		sleep 2
	done
	compose ps >&2 || true
	fail "network did not become healthy within 180 seconds"
}

fresh() {
	local started=$SECONDS
	require_isolated_profile
	check_prerequisites
	check_linux_data_filesystem
	[[ ! -e "$ACTIVE_FILE" ]] || fail "an active run exists; stop it and use reset before fresh"

	RUN_ID="run-$(date -u +%Y%m%d%H%M%S)-$$-$RANDOM"
	RUN_DIR="$STATE_DIR/$RUN_ID"
	PROJECT="pq3-$REPO_KEY-${RUN_ID#run-}"
	mkdir -m 700 -- "$RUN_DIR"
	printf 'schema=1\nproject=%s\n' "$PROJECT" > "$RUN_DIR/.pq3-run"
	printf '%s\n' "$RUN_ID" > "$ACTIVE_FILE"

	build_runtime_images
	if ! PACTWAY_HYBRID_PROFILE="$PROFILE" PACTWAY_ISOLATED_DEVELOPMENT=true \
		go -C "$ROOT" run ./cmd/pactway-pq-gen \
			-output="$RUN_DIR/material" \
			-configtx-dir="$ROOT/sampleconfig" \
			-fabric-profile=SampleAppChannelEtcdRaft \
			-channel-id="$CHANNEL_ID" \
			-orderer-host=orderer0.ordererorg.pactway.local \
			-orderer-port=7050 \
			-hybrid-profile="$PROFILE"; then
		fail "identity/genesis generation failed; this run is retained as secret material and can be removed with reset"
	fi

	mkdir -m 700 -- "$RUN_DIR/config"
	cp -- "$SCRIPT_DIR/compose.yaml" "$RUN_DIR/config/compose.yaml"
	cp -- "$ROOT/sampleconfig/orderer.yaml" "$RUN_DIR/config/orderer.yaml"
	COMPOSE_FILE="$RUN_DIR/config/compose.yaml"
	export PQ3_RUN_DIR="$RUN_DIR"
	export PQ3_MATERIAL_DIR="$RUN_DIR/material"
	export PQ3_IMAGE_TAG="$IMAGE_TAG"
	export PQ3_CHAINCODE_ID_ORG1=""
	export PQ3_CHAINCODE_ID_ORG2=""
	compose up --detach --wait --wait-timeout 180 orderer peer-org1 peer-org2
	wait_healthy
	record_duration fresh_total "$started"
	printf 'PQ3 network started. Run join to activate both peers on %s.\n' "$CHANNEL_ID"
	printf 'Private material is stored under %s/material/private; do not publish or reuse it.\n' "$RUN_DIR"
}

join_channel() {
	load_active
	local started=$SECONDS
	require_isolated_profile
	wait_healthy
	compose ps

	local orderer_channels
	orderer_channels="$(compose run --rm --no-deps cli-orderer-admin channel list \
		-o orderer0.ordererorg.pactway.local:9443 \
		--ca-file /run/public/organizations/OrdererOrg/msp/tlscacerts/tls-ca.pem \
		--client-cert /run/orderer-tls/client.crt \
		--client-key /run/orderer-tls/client.key)"
	if ! grep -Fq "\"name\": \"$CHANNEL_ID\"" <<<"$orderer_channels"; then
		compose run --rm --no-deps cli-orderer-admin channel join \
			--channelID "$CHANNEL_ID" \
			--config-block /run/public/genesis.block \
			-o orderer0.ordererorg.pactway.local:9443 \
			--ca-file /run/public/organizations/OrdererOrg/msp/tlscacerts/tls-ca.pem \
			--client-cert /run/orderer-tls/client.crt \
			--client-key /run/orderer-tls/client.key
	fi
	orderer_channels="$(compose run --rm --no-deps cli-orderer-admin channel list \
		-o orderer0.ordererorg.pactway.local:9443 \
		--ca-file /run/public/organizations/OrdererOrg/msp/tlscacerts/tls-ca.pem \
		--client-cert /run/orderer-tls/client.crt \
		--client-key /run/orderer-tls/client.key)"
	grep -Fq "\"name\": \"$CHANNEL_ID\"" <<<"$orderer_channels" ||
		fail "orderer did not report membership in $CHANNEL_ID after join"

	for service in cli-org1 cli-org2; do
		local output
		output="$(run_cli "$service" admin peer channel list)"
		if ! grep -Fq "$CHANNEL_ID" <<<"$output"; then
			run_cli "$service" admin peer channel join -b /run/public/genesis.block
			output="$(run_cli "$service" admin peer channel list)"
		fi
		grep -Fq "$CHANNEL_ID" <<<"$output" ||
			fail "$service did not report membership in $CHANNEL_ID"
	done
	printf '%s\n' "$orderer_channels" > "$RUN_DIR/evidence/orderer-channels.json"
	record_duration channel_join "$started"
	printf 'Both peers report membership in %s.\n' "$CHANNEL_ID"
}

deploy_chaincode() {
	load_active
	local started=$SECONDS
	require_isolated_profile
	wait_healthy
	run_cli cli-org1 admin peer channel list | grep -Fq "$CHANNEL_ID" ||
		fail "Org1 peer has not joined $CHANNEL_ID; run join first"
	run_cli cli-org2 admin peer channel list | grep -Fq "$CHANNEL_ID" ||
		fail "Org2 peer has not joined $CHANNEL_ID; run join first"

	local package_dir_org1="$RUN_DIR/package-org1"
	local package_dir_org2="$RUN_DIR/package-org2"
	local public_dir="$PQ3_MATERIAL_DIR/public"
	mkdir -m 700 -p -- "$package_dir_org1/code" "$package_dir_org2/code"
	mkdir -p -- "$public_dir"
	cat > "$package_dir_org1/metadata.json" <<EOF
{"type":"ccaas","label":"pq3asset_1.0"}
EOF
	cat > "$package_dir_org2/metadata.json" <<EOF
{"type":"ccaas","label":"pq3asset_1.0"}
EOF
	cat > "$package_dir_org1/code/connection.json" <<'EOF'
{
  "address": "pq3-chaincode-org1:9999",
  "dial_timeout": "10s",
  "tls_required": false
}
EOF
	cat > "$package_dir_org2/code/connection.json" <<'EOF'
{
  "address": "pq3-chaincode-org2:9999",
  "dial_timeout": "10s",
  "tls_required": false
}
EOF
	tar -czf "$package_dir_org1/code.tar.gz" -C "$package_dir_org1/code" connection.json
	tar -czf "$package_dir_org2/code.tar.gz" -C "$package_dir_org2/code" connection.json
	tar -czf "$public_dir/pq3asset-org1.tar.gz" -C "$package_dir_org1" metadata.json code.tar.gz
	tar -czf "$public_dir/pq3asset-org2.tar.gz" -C "$package_dir_org2" metadata.json code.tar.gz

	local package_id_org1 package_id_org2 installed
	package_id_org1="$(run_cli cli-org1 admin peer lifecycle chaincode calculatepackageid \
		/run/public/pq3asset-org1.tar.gz)"
	package_id_org2="$(run_cli cli-org2 admin peer lifecycle chaincode calculatepackageid \
		/run/public/pq3asset-org2.tar.gz)"
	[[ "$package_id_org1" == pq3asset_1.0:* && "$package_id_org2" == pq3asset_1.0:* ]] ||
		fail "unexpected CCAAS package identifiers: Org1=$package_id_org1 Org2=$package_id_org2"
	[[ "$package_id_org1" != "$package_id_org2" ]] ||
		fail "organization-specific CCAAS packages unexpectedly have the same identifier"
	installed="$(run_cli cli-org1 admin peer lifecycle chaincode queryinstalled)"
	if ! grep -Fq "$package_id_org1" <<<"$installed"; then
		run_cli cli-org1 admin peer lifecycle chaincode install /run/public/pq3asset-org1.tar.gz
	fi
	installed="$(run_cli cli-org2 admin peer lifecycle chaincode queryinstalled)"
	if ! grep -Fq "$package_id_org2" <<<"$installed"; then
		run_cli cli-org2 admin peer lifecycle chaincode install /run/public/pq3asset-org2.tar.gz
	fi

	local policy="AND('Org1MSP.peer','Org2MSP.peer')"
	run_cli cli-org1 admin peer lifecycle chaincode approveformyorg \
		-o orderer0.ordererorg.pactway.local:7050 --tls --cafile /run/public/organizations/OrdererOrg/msp/tlscacerts/tls-ca.pem \
		--channelID "$CHANNEL_ID" --name "$CHAINCODE_NAME" \
		--version "$CHAINCODE_VERSION" --package-id "$package_id_org1" \
		--sequence "$CHAINCODE_SEQUENCE" --signature-policy "$policy"
	run_cli cli-org2 admin peer lifecycle chaincode approveformyorg \
		-o orderer0.ordererorg.pactway.local:7050 --tls --cafile /run/public/organizations/OrdererOrg/msp/tlscacerts/tls-ca.pem \
		--channelID "$CHANNEL_ID" --name "$CHAINCODE_NAME" \
		--version "$CHAINCODE_VERSION" --package-id "$package_id_org2" \
		--sequence "$CHAINCODE_SEQUENCE" --signature-policy "$policy"
	run_cli cli-org1 admin peer lifecycle chaincode commit \
		-o orderer0.ordererorg.pactway.local:7050 --tls --cafile /run/public/organizations/OrdererOrg/msp/tlscacerts/tls-ca.pem \
		--channelID "$CHANNEL_ID" --name "$CHAINCODE_NAME" \
		--version "$CHAINCODE_VERSION" --sequence "$CHAINCODE_SEQUENCE" \
		--signature-policy "$policy" \
		--peerAddresses peer0.org1.pactway.local:7051 \
		--tlsRootCertFiles /run/public/organizations/Org1/msp/tlscacerts/tls-ca.pem \
		--peerAddresses peer0.org2.pactway.local:8051 \
		--tlsRootCertFiles /run/public/organizations/Org2/msp/tlscacerts/tls-ca.pem

	local committed
	committed="$(run_cli cli-org1 admin peer lifecycle chaincode querycommitted \
		--channelID "$CHANNEL_ID" --name "$CHAINCODE_NAME")"
	grep -Fq "Version: $CHAINCODE_VERSION" <<<"$committed" ||
		fail "committed definition did not report version $CHAINCODE_VERSION"
	grep -Fq "Sequence: $CHAINCODE_SEQUENCE" <<<"$committed" ||
		fail "committed definition did not report sequence $CHAINCODE_SEQUENCE"

	printf '%s\n' "$package_id_org1" > "$RUN_DIR/chaincode-id-org1"
	printf '%s\n' "$package_id_org2" > "$RUN_DIR/chaincode-id-org2"
	CHAINCODE_ID_ORG1="$package_id_org1"
	CHAINCODE_ID_ORG2="$package_id_org2"
	export PQ3_CHAINCODE_ID_ORG1="$CHAINCODE_ID_ORG1"
	export PQ3_CHAINCODE_ID_ORG2="$CHAINCODE_ID_ORG2"
	compose up --detach --wait --wait-timeout 60 ccaas-org1 ccaas-org2
	wait_healthy
	printf '%s\n' "$committed" > "$RUN_DIR/evidence/chaincode-definition.txt"
	{
		printf 'Org1MSP=%s\n' "$package_id_org1"
		printf 'Org2MSP=%s\n' "$package_id_org2"
	} > "$RUN_DIR/evidence/chaincode-package-ids.txt"
	record_duration chaincode_deploy "$started"
	printf 'Committed %s v%s with endorsement policy %s.\n' \
		"$CHAINCODE_NAME" "$CHAINCODE_VERSION" "$policy"
	printf 'Org1 and Org2 installed and approved distinct CCAAS package IDs: %s %s\n' \
		"$package_id_org1" "$package_id_org2"
}

submit_asset_transaction() {
	local function="$1" key="$2" value="$3"
	local started=$SECONDS orderer_tls org1_tls org2_tls args invoke_output
	orderer_tls=/run/public/organizations/OrdererOrg/msp/tlscacerts/tls-ca.pem
	org1_tls=/run/public/organizations/Org1/msp/tlscacerts/tls-ca.pem
	org2_tls=/run/public/organizations/Org2/msp/tlscacerts/tls-ca.pem
	printf -v args '{"function":"%s","Args":["%s","%s"]}' "$function" "$key" "$value"
	if ! invoke_output="$(run_timed_cli cli-org1 client peer chaincode invoke \
		-o orderer0.ordererorg.pactway.local:7050 --tls --cafile "$orderer_tls" \
		-C "$CHANNEL_ID" -n "$CHAINCODE_NAME" -c "$args" \
		--peerAddresses peer0.org1.pactway.local:7051 --tlsRootCertFiles "$org1_tls" \
		--peerAddresses peer0.org2.pactway.local:8051 --tlsRootCertFiles "$org2_tls" \
		--waitForEvent --waitForEventTimeout 60s 2>&1)"; then
		fail "$function invoke failed: $invoke_output"
	fi

	local -a committed_txids
	mapfile -t committed_txids < <(
		grep -Eo 'txid \[[[:xdigit:]]{64}\] committed with status \(VALID\)' <<<"$invoke_output" |
			sed -E 's/txid \[([[:xdigit:]]{64})\].*/\1/' |
			sort -u
	)
	[[ "${#committed_txids[@]}" -eq 1 ]] ||
		fail "$function did not produce exactly one committed transaction ID: $invoke_output"
	local txid="${committed_txids[0]}"
	record_stage_timings "$txid" "$invoke_output"

	local org1_value org2_value
	org1_value="$(run_cli cli-org1 client peer chaincode query \
		-C "$CHANNEL_ID" -n "$CHAINCODE_NAME" \
		-c "{\"function\":\"Get\",\"Args\":[\"$key\"]}")"
	org2_value="$(run_cli cli-org2 client peer chaincode query \
		-C "$CHANNEL_ID" -n "$CHAINCODE_NAME" \
		-c "{\"function\":\"Get\",\"Args\":[\"$key\"]}")"
	[[ "$org1_value" == "$value" ]] ||
		fail "Org1 query after $txid returned unexpected asset value: $org1_value"
	[[ "$org2_value" == "$value" ]] ||
		fail "Org2 query after $txid returned unexpected asset value: $org2_value"

	printf '%s %s\n' "$txid" "$function" >> "$RUN_DIR/evidence/transaction-ids.txt"
	CURRENT_STATE_KEY="$key"
	CURRENT_STATE_VALUE="$value"
	printf '%s\n' "$CURRENT_STATE_KEY" > "$RUN_DIR/current-state-key"
	printf '%s\n' "$CURRENT_STATE_VALUE" > "$RUN_DIR/current-state-value"
	local report_name="transaction-$txid.json"
	verify_evidence "$txid" "$key" "$value" "$org1_value" "$org2_value" "$report_name"
	if [[ "$function" == Set ]]; then
		cp -- "$RUN_DIR/evidence/$report_name" "$RUN_DIR/evidence/transaction-verification.json"
	fi
	local sample_number
	sample_number="$(grep -c . "$RUN_DIR/evidence/transaction-ids.txt")"
	record_duration "transaction_${sample_number}_${function}" "$started"
	printf 'Both peers committed transaction %s and read %s=%s.\n' "$txid" "$key" "$value"
}

record_stage_timings() {
	local expected_txid="$1" output="$2"
	local line marker stage_field txid_field started_field completed_field duration_field
	local stage txid started completed duration count=0
	while IFS= read -r line; do
		read -r marker stage_field txid_field started_field completed_field duration_field <<<"$line"
		[[ "$marker" == "PQ3_STAGE_TIMING" ]] || continue
		stage="${stage_field#stage=}"
		txid="${txid_field#txid=}"
		started="${started_field#started_at=}"
		completed="${completed_field#completed_at=}"
		duration="${duration_field#duration_ms=}"
		[[ "$txid" == "$expected_txid" ]] ||
			fail "stage timing was reported for an unexpected transaction: $txid"
		[[ "$duration" =~ ^[0-9]+$ ]] ||
			fail "stage timing has an invalid duration: $duration"
		case "$stage" in
			proposal_preparation|endorsement_collection|ordering_submission|finality_wait) ;;
			*) fail "unexpected transaction timing stage: $stage" ;;
		esac
		printf '{"transaction_id":"%s","stage":"%s","started_at_utc":"%s","completed_at_utc":"%s","duration_ms":%s}\n' \
			"$txid" "$stage" "$started" "$completed" "$duration" \
			>> "$RUN_DIR/evidence/stage-timings.jsonl"
		((count += 1))
	done < <(grep -F 'PQ3_STAGE_TIMING ' <<<"$output" || true)
	[[ "$count" -eq 4 ]] ||
		fail "expected four local timing observations for transaction $expected_txid; found $count"
}

invoke_asset() {
	load_active
	local started=$SECONDS
	[[ -n "$CHAINCODE_ID_ORG1" && -n "$CHAINCODE_ID_ORG2" ]] ||
		fail "chaincode is not deployed; run deploy first"
	require_isolated_profile
	wait_healthy
	mkdir -p -- "$RUN_DIR/evidence"
	CURRENT_STATE_KEY="pq3-asset-$(date -u +%Y%m%d%H%M%S)-$$-$RANDOM"
	submit_asset_transaction InitAsset "$CURRENT_STATE_KEY" initial-value
	submit_asset_transaction Set "$CURRENT_STATE_KEY" updated-value-1
	record_duration invoke_and_verify "$started"
}

reject_missing_endorsement() {
	load_active
	[[ -n "$CHAINCODE_ID_ORG1" && -n "$CHAINCODE_ID_ORG2" ]] ||
		fail "chaincode is not deployed; run deploy first"
	[[ -n "$CURRENT_STATE_KEY" && -n "$CURRENT_STATE_VALUE" ]] ||
		fail "no successful asset transaction is available for comparison"
	require_isolated_profile
	wait_healthy

	local before_org1 before_org2 after_org1 after_org2 invoke_output invoke_status verification_output txid
	before_org1="$(run_cli cli-org1 client peer chaincode query \
		-C "$CHANNEL_ID" -n "$CHAINCODE_NAME" \
		-c "{\"function\":\"Get\",\"Args\":[\"$CURRENT_STATE_KEY\"]}")"
	before_org2="$(run_cli cli-org2 client peer chaincode query \
		-C "$CHANNEL_ID" -n "$CHAINCODE_NAME" \
		-c "{\"function\":\"Get\",\"Args\":[\"$CURRENT_STATE_KEY\"]}")"
	[[ "$before_org1" == "$CURRENT_STATE_VALUE" && "$before_org2" == "$CURRENT_STATE_VALUE" ]] ||
		fail "peer state before negative invocation was unexpected: Org1=$before_org1 Org2=$before_org2"
	if invoke_output="$(run_cli cli-org1 client peer chaincode invoke \
		-o orderer0.ordererorg.pactway.local:7050 --tls \
		--cafile /run/public/organizations/OrdererOrg/msp/tlscacerts/tls-ca.pem \
		-C "$CHANNEL_ID" -n "$CHAINCODE_NAME" \
		-c "{\"function\":\"Set\",\"Args\":[\"$CURRENT_STATE_KEY\",\"must-not-commit\"]}" \
		--peerAddresses peer0.org1.pactway.local:7051 \
		--tlsRootCertFiles /run/public/organizations/Org1/msp/tlscacerts/tls-ca.pem \
		--waitForEvent --waitForEventTimeout 60s 2>&1)"; then
		invoke_status=0
	else
		invoke_status=$?
	fi
	after_org1="$(run_cli cli-org1 client peer chaincode query \
		-C "$CHANNEL_ID" -n "$CHAINCODE_NAME" \
		-c "{\"function\":\"Get\",\"Args\":[\"$CURRENT_STATE_KEY\"]}")"
	after_org2="$(run_cli cli-org2 client peer chaincode query \
		-C "$CHANNEL_ID" -n "$CHAINCODE_NAME" \
		-c "{\"function\":\"Get\",\"Args\":[\"$CURRENT_STATE_KEY\"]}")"
	[[ "$before_org1" == "$after_org1" && "$before_org2" == "$after_org2" ]] ||
		fail "single-organization endorsement changed committed state: before=($before_org1,$before_org2) after=($after_org1,$after_org2)"
	[[ "$invoke_output" == *"ENDORSEMENT_POLICY_FAILURE"* ]] ||
		fail "single-organization invoke did not report endorsement policy failure: $invoke_output"
	local -a rejected_txids
	mapfile -t rejected_txids < <(
		grep -Eo 'txid \[[[:xdigit:]]{64}\] committed with status \(ENDORSEMENT_POLICY_FAILURE\)' <<<"$invoke_output" |
			sed -E 's/txid \[([[:xdigit:]]{64})\].*/\1/' |
			sort -u
	)
	[[ "${#rejected_txids[@]}" -eq 1 ]] ||
		fail "single-organization invocation did not identify exactly one rejected transaction: $invoke_output"
	txid="${rejected_txids[0]}"
	if verification_output="$(verify_evidence "$txid" "$CURRENT_STATE_KEY" "$CURRENT_STATE_VALUE" \
		"$after_org1" "$after_org2" missing-endorsement-verification.json 2>&1)"; then
		fail "evidence verifier accepted invalid transaction $txid"
	fi
	grep -Fq "validation code ENDORSEMENT_POLICY_FAILURE" <<<"$verification_output" ||
		fail "invalid transaction was rejected for an unexpected reason: $verification_output"

	{
		printf 'tx_id=%s\n' "$txid"
		printf 'single_endorser_invoke_exit_code=%s\n' "$invoke_status"
		printf 'validation_code=ENDORSEMENT_POLICY_FAILURE\n'
		printf 'state_before_org1=%s\n' "$before_org1"
		printf 'state_before_org2=%s\n' "$before_org2"
		printf 'state_after_org1=%s\n' "$after_org1"
		printf 'state_after_org2=%s\n' "$after_org2"
		printf 'verifier_rejection=transaction validation code ENDORSEMENT_POLICY_FAILURE\n'
	} > "$RUN_DIR/evidence/missing-endorsement.txt"
	printf 'Rejected transaction %s with ENDORSEMENT_POLICY_FAILURE; both peer ledgers retained the prior value.\n' "$txid"
}

assert_persisted_network_state() {
	local stage="$1" channels value
	wait_healthy
	for service in cli-org1 cli-org2; do
		channels="$(run_cli "$service" admin peer channel list)"
		grep -Fq "$CHANNEL_ID" <<<"$channels" ||
			fail "$service lost $CHANNEL_ID after $stage"
	done
	local orderer_channels
	orderer_channels="$(compose run --rm --no-deps cli-orderer-admin channel list \
		-o orderer0.ordererorg.pactway.local:9443 \
		--ca-file /run/public/organizations/OrdererOrg/msp/tlscacerts/tls-ca.pem \
		--client-cert /run/orderer-tls/client.crt \
		--client-key /run/orderer-tls/client.key)"
	grep -Fq "\"name\": \"$CHANNEL_ID\"" <<<"$orderer_channels" ||
		fail "orderer lost $CHANNEL_ID after $stage"
	[[ -n "$CURRENT_STATE_KEY" && -n "$CURRENT_STATE_VALUE" ]] ||
		fail "no committed asset state is available after $stage"
	for service in cli-org1 cli-org2; do
		value="$(run_cli "$service" client peer chaincode query \
			-C "$CHANNEL_ID" -n "$CHAINCODE_NAME" \
			-c "{\"function\":\"Get\",\"Args\":[\"$CURRENT_STATE_KEY\"]}")"
		[[ "$value" == "$CURRENT_STATE_VALUE" ]] ||
			fail "$service returned unexpected state after $stage: $value"
	done
	printf '%s: channel active and state preserved (%s)\n' "$stage" "$value"
}

exercise_recovery() {
	load_active
	local started=$SECONDS
	require_isolated_profile
	[[ -n "$CHAINCODE_ID_ORG1" && -n "$CHAINCODE_ID_ORG2" ]] ||
		fail "chaincode is not deployed; run deploy first"
	assert_persisted_network_state "before lifecycle cycle"
	stop_network
	start_network
	assert_persisted_network_state "start"
	restart_network
	assert_persisted_network_state "restart"
	resume_network
	assert_persisted_network_state "resume"
	{
		printf 'run_id=%s\n' "$RUN_ID"
		printf 'channel_id=%s\n' "$CHANNEL_ID"
		printf 'chaincode_id_org1=%s\n' "$CHAINCODE_ID_ORG1"
		printf 'chaincode_id_org2=%s\n' "$CHAINCODE_ID_ORG2"
		printf 'lifecycle=stop,start,restart,resume\n'
		printf 'both_peer_state_key=%s\n' "$CURRENT_STATE_KEY"
		printf 'both_peer_state=%s\n' "$CURRENT_STATE_VALUE"
	} > "$RUN_DIR/evidence/recovery.txt"
	record_duration recovery_cycle "$started"
}

verify_evidence() {
	load_active
	require_isolated_profile
	[[ -n "$CHAINCODE_ID_ORG1" && -n "$CHAINCODE_ID_ORG2" ]] ||
		fail "chaincode is not deployed; run deploy first"
	local txid="${1:-}" state_key="${2:-}" expected_value="${3:-}"
	local org1_state="${4:-}" org2_state="${5:-}"
	local report_name="${6:-transaction-verification.json}"
	[[ "$txid" =~ ^[[:xdigit:]]{64}$ ]] || fail "a transaction ID is required for verification"
	[[ -n "$state_key" ]] || fail "the state key is required for verification"
	[[ -n "$expected_value" ]] || fail "the expected state value is required for verification"
	[[ "$report_name" =~ ^[A-Za-z0-9._-]+$ ]] || fail "invalid evidence report name"
	mkdir -p -- "$RUN_DIR/evidence"
	[[ -n "$org1_state" && -n "$org2_state" ]] ||
		fail "state reads from both peers are required for transaction verification"
	local block_file="$RUN_DIR/evidence/block-$txid.hex"
	local org1_transaction_file="$RUN_DIR/evidence/org1-transaction-$txid.hex"
	local org2_transaction_file="$RUN_DIR/evidence/org2-transaction-$txid.hex"
	local query_block query_transaction
	printf -v query_block '{"function":"GetBlockByTxID","Args":["%s","%s"]}' "$CHANNEL_ID" "$txid"
	printf -v query_transaction '{"function":"GetTransactionByID","Args":["%s","%s"]}' "$CHANNEL_ID" "$txid"
	run_cli cli-org1 admin peer chaincode query \
		-C "$CHANNEL_ID" -n qscc -c "$query_block" --hex > "$block_file"
	run_cli cli-org1 admin peer chaincode query \
		-C "$CHANNEL_ID" -n qscc -c "$query_transaction" --hex > "$org1_transaction_file"
	run_cli cli-org2 admin peer chaincode query \
		-C "$CHANNEL_ID" -n qscc -c "$query_transaction" --hex > "$org2_transaction_file"
	compose run --rm --no-deps \
		--volume "$RUN_DIR/evidence:/run/evidence" \
		-e PACTWAY_HYBRID_PROFILE="$PROFILE" \
		-e PACTWAY_ISOLATED_DEVELOPMENT=true \
		--entrypoint /usr/local/bin/pq3-verify cli-orderer-admin \
		--config-block /run/public/genesis.block \
		--block "/run/evidence/block-$txid.hex" \
		--require-chaincode "$CHAINCODE_NAME" \
		--require-orgs Org1MSP,Org2MSP \
		--tx-id "$txid" \
		--processed-transaction-org1 "/run/evidence/org1-transaction-$txid.hex" \
		--processed-transaction-org2 "/run/evidence/org2-transaction-$txid.hex" \
		--require-state-key "$state_key" \
		--require-state-value "$expected_value" \
		--org1-state "$org1_state" \
		--org2-state "$org2_state" |
		tee "$RUN_DIR/evidence/$report_name"
}

show_status() {
	load_active
	compose ps
}

stop_network() {
	load_active
	compose stop
}

start_network() {
	load_active
	compose start
	wait_healthy
}

restart_network() {
	load_active
	compose restart
	wait_healthy
}

resume_network() {
	load_active
	local services=(orderer peer-org1 peer-org2)
	if [[ -n "$CHAINCODE_ID_ORG1" && -n "$CHAINCODE_ID_ORG2" ]]; then
		services+=(ccaas-org1 ccaas-org2)
	fi
	compose up --detach --wait --wait-timeout 180 --pull never "${services[@]}"
	wait_healthy
}

verify_latest_transaction() {
	load_active
	[[ -f "$RUN_DIR/evidence/transaction-ids.txt" ]] ||
		fail "no successful transaction evidence is available; run invoke first"
	local txid org1_state org2_state
	txid="$(tail -n1 "$RUN_DIR/evidence/transaction-ids.txt" | cut -d ' ' -f1)"
	[[ -n "$CURRENT_STATE_KEY" && -n "$CURRENT_STATE_VALUE" ]] ||
		fail "the latest committed state is unavailable"
	org1_state="$(run_cli cli-org1 client peer chaincode query \
		-C "$CHANNEL_ID" -n "$CHAINCODE_NAME" \
		-c "{\"function\":\"Get\",\"Args\":[\"$CURRENT_STATE_KEY\"]}")"
	org2_state="$(run_cli cli-org2 client peer chaincode query \
		-C "$CHANNEL_ID" -n "$CHAINCODE_NAME" \
		-c "{\"function\":\"Get\",\"Args\":[\"$CURRENT_STATE_KEY\"]}")"
	verify_evidence "$txid" "$CURRENT_STATE_KEY" "$CURRENT_STATE_VALUE" \
		"$org1_state" "$org2_state" transaction-verification.json
}

reset_network() {
	load_active
	[[ "$RUN_DIR" == "$STATE_DIR/$RUN_ID" && "$RUN_DIR" != "$STATE_ROOT" ]] ||
		fail "refusing to reset a path outside the PQ3 run directory"
	[[ "$(dirname -- "$RUN_DIR")" == "$STATE_DIR" ]] ||
		fail "refusing to reset a non-child PQ3 run directory"
	if [[ -f "$COMPOSE_FILE" && -n "$IMAGE_TAG" ]]; then
		compose down --volumes --remove-orphans
	fi
	rm -rf -- "$RUN_DIR"
	rm -f -- "$ACTIVE_FILE"
	printf 'Reset only PQ3 run %s and its Compose project volumes.\n' "$RUN_ID"
}

run_acceptance_step() {
	local label="$1"
	shift
	local log_file="$ACCEPTANCE_LOG_DIR/step-${#ACCEPTANCE_STEPS[@]}.log"
	local command_text status=0
	printf -v command_text '%q ' "$@"
	ACCEPTANCE_CURRENT_STEP="$label"
	if [[ "$1" == "$SCRIPT_DIR/pq3.sh" ]]; then
		if PQ3_STATE_ROOT="$ACCEPTANCE_STATE_ROOT" "$@" > "$log_file" 2>&1; then
			status=0
		else
			status=$?
		fi
	else
		if "$@" > "$log_file" 2>&1; then
			status=0
		else
			status=$?
		fi
	fi
	if [[ "$status" -eq 0 ]]; then
		ACCEPTANCE_STEPS+=("$label"$'\t'"$command_text"$'\t'passed)
	else
		ACCEPTANCE_STEPS+=("$label"$'\t'"$command_text"$'\t'"failed (exit $status)")
		tail -n 40 "$log_file" >&2
	fi
	local acceptance_active_file="$ACCEPTANCE_STATE_ROOT/$REPO_KEY/active-run"
	if [[ "$label" == "Build, generate, and start network" && -f "$acceptance_active_file" ]]; then
		ACCEPTANCE_RUN_ID="$(<"$acceptance_active_file")"
	fi
	ACCEPTANCE_CURRENT_STEP=""
	return "$status"
}

acceptance_step_result() {
	local expected="$1" step label command_text result
	for step in "${ACCEPTANCE_STEPS[@]}"; do
		IFS=$'\t' read -r label command_text result <<<"$step"
		if [[ "$label" == "$expected" ]]; then
			printf '%s' "$result"
			return
		fi
	done
	printf 'not run'
}

acceptance_finalize() {
	local status="$1" cleanup_status=0 source_commit source_branch source_dirty
	trap - EXIT
	local run_dir=""
	local acceptance_active_file="$ACCEPTANCE_STATE_ROOT/$REPO_KEY/active-run"
	if [[ -n "$ACCEPTANCE_RUN_ID" && -f "$acceptance_active_file" &&
		"$(<"$acceptance_active_file")" == "$ACCEPTANCE_RUN_ID" ]]; then
		local run_id
		run_id="$(<"$acceptance_active_file")"
		if [[ "$run_id" =~ ^run-[0-9]+-[0-9]+-[0-9]+$ ]]; then
			run_dir="$ACCEPTANCE_STATE_ROOT/$REPO_KEY/$run_id"
		fi
	fi

	if [[ -n "$run_dir" && -d "$run_dir/evidence" ]]; then
		local evidence_output="$ACCEPTANCE_OUTPUT_DIR/evidence"
		mkdir -p -- "$evidence_output"
		for file in network-manifest.json orderer-channels.json chaincode-definition.txt \
			transaction-ids.txt transaction-verification.json stage-timings.jsonl \
			timings.txt missing-endorsement.txt recovery.txt; do
			if [[ -f "$run_dir/evidence/$file" ]]; then
				cp -- "$run_dir/evidence/$file" "$evidence_output/$file"
			fi
		done
		if [[ -f "$run_dir/evidence/stage-timings.jsonl" ]]; then
			local stage count
			{
				printf '{"measurement_source":"local CLI observations","limitations":"ordering_submission is the local broadcast call through its acknowledgment, not orderer consensus; finality_wait measures delivery of the transaction to all configured peers","samples":{'
				local separator=""
				for stage in proposal_preparation endorsement_collection ordering_submission finality_wait; do
					count="$(grep -c "\"stage\":\"$stage\"" "$run_dir/evidence/stage-timings.jsonl" || true)"
					printf '%s"%s":%s' "$separator" "$stage" "${count:-0}"
					separator=","
				done
				printf '}}\n'
			} > "$evidence_output/stage-timing-summary.json"
		fi
	fi

	if [[ -n "$ACCEPTANCE_RUN_ID" && -f "$acceptance_active_file" &&
		"$(<"$acceptance_active_file")" == "$ACCEPTANCE_RUN_ID" ]]; then
		if PQ3_STATE_ROOT="$ACCEPTANCE_STATE_ROOT" "$SCRIPT_DIR/pq3.sh" reset \
			> "$ACCEPTANCE_LOG_DIR/reset.log" 2>&1; then
			ACCEPTANCE_STEPS+=("Scoped runtime cleanup"$'\t'"$SCRIPT_DIR/pq3.sh reset"$'\t'passed)
		else
			cleanup_status=$?
			ACCEPTANCE_STEPS+=("Scoped runtime cleanup"$'\t'"$SCRIPT_DIR/pq3.sh reset"$'\t'"failed (exit $cleanup_status)")
			cat "$ACCEPTANCE_LOG_DIR/reset.log" >&2
			status=1
		fi
		rmdir -- "$ACCEPTANCE_STATE_ROOT/$REPO_KEY" "$ACCEPTANCE_STATE_ROOT" 2>/dev/null || true
	fi

	source_commit="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || printf unknown)"
	source_branch="$(git -C "$ROOT" branch --show-current 2>/dev/null || printf unknown)"
	if [[ -n "$(git -C "$ROOT" status --porcelain --untracked-files=all 2>/dev/null)" ]]; then
		source_dirty=true
	else
		source_dirty=false
	fi
	{
		printf '# PQ3 Isolated Acceptance Report\n\n'
		printf -- '- Result: **%s**\n' "$([[ "$status" -eq 0 ]] && printf PASS || printf FAIL)"
		printf -- '- Candidate gate commit: `%s`\n' "$source_commit"
		printf -- '- Branch: `%s` (worktree dirty: `%s`)\n' "$source_branch" "$source_dirty"
		printf -- '- Profile: `%s`; isolated development only; transport: classical TLS.\n' "$PROFILE"
		printf -- '- Generated credentials, ledgers, raw test logs, and block bytes are not included.\n\n'
		printf '## Commands and results\n\n| Step | Command | Result |\n|---|---|---|\n'
		local step label command_text result
		for step in "${ACCEPTANCE_STEPS[@]}"; do
			IFS=$'\t' read -r label command_text result <<<"$step"
			printf '| %s | `%s` | %s |\n' "$label" "$command_text" "$result"
		done
		printf '\n## Gate commits and results\n\n| Gate | Candidate commit | Result |\n|---|---|---|\n'
		printf '| PQ3.0 reproducible deployment | `%s` | %s |\n' \
			"$source_commit" "$(acceptance_step_result "Build, generate, and start network")"
		printf '| PQ3.1 channel activation and recovery | `%s` | %s / %s |\n' \
			"$source_commit" "$(acceptance_step_result "Join orderer and both peers")" \
			"$(acceptance_step_result "Verify persistence and recovery")"
		printf '| PQ3.2 transaction and evidence | `%s` | %s / %s |\n' \
			"$source_commit" "$(acceptance_step_result "Invoke and verify repeated transaction samples")" \
			"$(acceptance_step_result "Re-verify latest exact transaction")"
		printf '| PQ3.3 negative acceptance | `%s` | %s / %s |\n' \
			"$source_commit" "$(acceptance_step_result "Hybrid MSP network acceptance")" \
			"$(acceptance_step_result "Reject missing endorsement")"
		printf '| PQ3.4 automation and evidence handoff | `%s` | %s |\n' \
			"$source_commit" "$([[ "$status" -eq 0 ]] && printf PASS || printf FAIL)"
		printf '\nThe candidate commit above is the source revision used for every gate. A dirty worktree means the tested source also includes uncommitted changes and is not represented by that commit alone.\n'
		printf '\n## Timing scope and limitations\n\nStage durations are local wall-clock observations with UTC start/end timestamps and millisecond resolution. They are not signed protocol timestamps. The broadcast-call observation does not isolate ordering consensus; finality wait ends when delivery reports the transaction at all configured peers. Counts are included in `evidence/stage-timing-summary.json`.\n'
		printf '\n## Unresolved limitations\n\n- The demo uses the temporary `rfc5612-test-only-v1` profile and classical TLS; it makes no production, PQ transport, HA, or BFT claim.\n'
		if [[ -z "${PACTWAY_UPSTREAM_PEER:-}" ]]; then
			printf -- '- Upstream-peer compatibility test was skipped because `PACTWAY_UPSTREAM_PEER` was not set to a verified binary.\n'
		else
			printf -- '- Upstream-peer compatibility test used the binary configured by `PACTWAY_UPSTREAM_PEER`; verify its provenance separately.\n'
		fi
	} > "$ACCEPTANCE_OUTPUT_DIR/report.md"
	rm -rf -- "$ACCEPTANCE_LOG_DIR"
	printf 'Sanitized PQ3 acceptance evidence: %s\n' "$ACCEPTANCE_OUTPUT_DIR"
	exit "$status"
}

acceptance() {
	local output_root="${PQ3_EVIDENCE_OUTPUT:-$ROOT/build/pq3/acceptance-evidence}"
	case "$output_root/" in
		"$STATE_ROOT/"*) fail "acceptance evidence output must be outside the private runtime directory" ;;
	esac
	mkdir -p -- "$output_root"
	ACCEPTANCE_OUTPUT_DIR="$output_root/acceptance-$(date -u +%Y%m%dT%H%M%SZ)-$$"
	mkdir -m 700 -- "$ACCEPTANCE_OUTPUT_DIR"
	ACCEPTANCE_LOG_DIR="$(mktemp -d)"
	ACCEPTANCE_STATE_ROOT="$STATE_ROOT/acceptance-$(date -u +%Y%m%dT%H%M%SZ)-$$"
	trap 'acceptance_finalize "$?"' EXIT

	if [[ "${PACTWAY_HYBRID_PROFILE:-}" != "$PROFILE" ||
		"${PACTWAY_ISOLATED_DEVELOPMENT:-}" != "true" ]]; then
		ACCEPTANCE_STEPS+=("Development-only profile guard"$'\t'"required profile and isolation variables"$'\t'failed)
		fail "set PACTWAY_HYBRID_PROFILE=$PROFILE and PACTWAY_ISOLATED_DEVELOPMENT=true explicitly"
	fi
	ACCEPTANCE_STEPS+=("Development-only profile guard"$'\t'"required profile and isolation variables"$'\t'passed)
	local ginkgo_focus='Pactway hybrid transaction (expiry replay|signature rejection)|persists the rotation before signer activation|Pactway hybrid network negative acceptance|Upstream channel capability compatibility'
	run_acceptance_step "Shell syntax" bash -n "$SCRIPT_DIR/pq3.sh"
	run_acceptance_step "Integration prerequisites" make -C "$ROOT" integration-test-prereqs
	run_acceptance_step "Unit and tool validation" go -C "$ROOT" test -mod=vendor \
		./cmd/pq3-verify ./integration/pq3 ./pq-crypto ./msp ./common/channelconfig \
		./common/configtx ./orderer/common/msgprocessor
	run_acceptance_step "Hybrid MSP network acceptance" go -C "$ROOT" test \
		-timeout=40m -mod=vendor ./integration/msp "-ginkgo.focus=$ginkgo_focus" -ginkgo.v
	run_acceptance_step "Build verifier and chaincode" go -C "$ROOT" build -mod=vendor \
		./cmd/pq3-verify ./integration/pq3
	run_acceptance_step "Build, generate, and start network" "$SCRIPT_DIR/pq3.sh" fresh
	run_acceptance_step "Join orderer and both peers" "$SCRIPT_DIR/pq3.sh" join
	run_acceptance_step "Deploy organization-specific chaincode" "$SCRIPT_DIR/pq3.sh" deploy
	run_acceptance_step "Invoke and verify repeated transaction samples" "$SCRIPT_DIR/pq3.sh" invoke
	run_acceptance_step "Re-verify latest exact transaction" "$SCRIPT_DIR/pq3.sh" verify
	run_acceptance_step "Reject missing endorsement" "$SCRIPT_DIR/pq3.sh" negative-endorsement
	run_acceptance_step "Verify persistence and recovery" "$SCRIPT_DIR/pq3.sh" recovery
}

usage() {
	cat <<'EOF'
Usage: integration/pq3/pq3.sh COMMAND

Commands:
  fresh    Build source-pinned local images, generate fresh keys/genesis, and start nodes
  join     Join Org1 and Org2 peers to the generated application channel
  deploy   Install, approve, and commit the CCAAS chaincode with two-org policy
  invoke   Submit a two-peer-endorsed transaction and verify state at both peers
  negative-endorsement  Verify a single-org endorsement cannot update state
  recovery   Exercise stop/start/restart/resume while preserving ledger state
  verify   Verify the latest transaction and peer-ledger commit evidence
  acceptance  Run all validation and network gates, export sanitized evidence, then reset
  health   Show node health and wait for node health checks
  status   Show Compose service status
  stop     Stop this run without deleting credentials, configuration, or ledgers
  start    Start stopped containers without regenerating identities or genesis
  restart  Restart containers while preserving credentials and ledgers
  resume   Reconcile/start this run from its saved Compose configuration
  reset    Remove only this run's containers, network, volumes, and generated material
EOF
}

command="${1:-}"
case "$command" in
	fresh)
		fresh
		;;
	join)
		shift
		join_channel
		;;
	deploy)
		deploy_chaincode
		;;
	invoke)
		shift
		invoke_asset
		;;
	negative-endorsement)
		reject_missing_endorsement
		;;
	recovery)
		exercise_recovery
		;;
	acceptance)
		acceptance
		;;
	verify)
		shift
		verify_latest_transaction
		;;
	health)
		shift
		load_active
		wait_healthy
		compose ps
		;;
	status)
		show_status
		;;
	stop)
		stop_network
		;;
	start)
		start_network
		;;
	restart)
		restart_network
		;;
	resume)
		resume_network
		;;
	reset)
		reset_network
		;;
	*)
		usage
		[[ -z "$command" ]] || exit 2
		;;
esac
