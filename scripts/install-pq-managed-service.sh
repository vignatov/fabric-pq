#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

# Run on the provisioned Linux VM as root, from a trusted copy of this
# repository. This installs the unit and launcher but does not start a node.
set -euo pipefail

if [[ $EUID -ne 0 || $# -ne 1 ]]; then
    echo "usage: sudo $0 /absolute/path/to/pq-launcher" >&2
    exit 2
fi

launcher=$1
if [[ $launcher != /* || ! -f $launcher || ! -x $launcher ]]; then
    echo "launcher must be an absolute path to an executable file" >&2
    exit 1
fi

id fabric-pq >/dev/null
getent group fabric-pq >/dev/null
command -v getfacl >/dev/null || { echo "getfacl is required to validate trusted paths" >&2; exit 1; }
[[ -d /var/lib/fabric-pq ]] || { echo "provision /var/lib/fabric-pq first" >&2; exit 1; }

# Check evidence and every ancestor: the service account must not be able to
# replace a file, a directory entry, or a path component. Mount policy remains
# an additional provisioning responsibility.
check_root_owned_path() {
    local path=$1 resolved owner mode acl
    resolved=$(realpath -e -- "$path")
    [[ $resolved == "$path" ]] || { echo "symlink in trusted path: $path" >&2; return 1; }
    while :; do
        read -r owner mode < <(stat -c '%u %a' -- "$path")
        if [[ $owner != 0 ]] || (( (8#$mode & 0022) != 0 )); then
            echo "trusted path is not root-owned and non-writable by others: $path" >&2
            return 1
        fi
        acl=$(getfacl -cp -- "$path") || return 1
        if grep -Eq '^(user|group):[^:]+:|^default:' <<< "$acl"; then
            echo "trusted path has an extended or default ACL: $path" >&2
            return 1
        fi
        [[ $path == / ]] && break
        path=$(dirname -- "$path")
    done
}

for evidence in /etc/fabric-pq/enrollment/authority.pub /etc/fabric-pq/enrollment/manifest.json /etc/fabric-pq/enrollment/history.json; do
    [[ -f $evidence ]] || { echo "missing provisioning evidence: $evidence" >&2; exit 1; }
    check_root_owned_path "$evidence"
done

if [[ -e /etc/systemd/system/fabric-pq-managed.service.d || -L /etc/systemd/system/fabric-pq-managed.service.d ]]; then
    echo "remove or audit managed-service drop-ins before installation" >&2
    exit 1
fi
if systemctl is-active --quiet fabric-pq-managed.service; then
    echo "stop the managed service before replacing its launcher" >&2
    exit 1
fi

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
unit_source=$(realpath -e -- "$script_dir/../sampleconfig/fabric-pq-managed.service")
check_root_owned_path "$launcher"
check_root_owned_path "$unit_source"
check_root_owned_path /usr/local/libexec
check_root_owned_path /etc/systemd/system
if [[ -L /usr/local/libexec/fabric-pq || -L /usr/local/libexec/fabric-pq/pq-launcher || -L /etc/systemd/system/fabric-pq-managed.service ]]; then
    echo "refusing a symlink at an installation destination" >&2
    exit 1
fi
install -d -o root -g root -m 0755 /usr/local/libexec/fabric-pq
check_root_owned_path /usr/local/libexec/fabric-pq
install -o root -g root -m 0755 -- "$launcher" /usr/local/libexec/fabric-pq/pq-launcher
install -o root -g root -m 0644 -- "$unit_source" /etc/systemd/system/fabric-pq-managed.service
systemctl daemon-reload
echo "Installed fabric-pq-managed.service; audit other Fabric services before enabling it."
