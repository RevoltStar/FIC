#!/usr/bin/env bash
set -euo pipefail
[[ $# == 2 ]] || { echo 'usage: run-native.sh SYSTEMD_IMAGE EVIDENCE_DIRECTORY' >&2; exit 2; }
image=$1
out=$(realpath -m "$2")
root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
mkdir -p "$out"
name="fic-dm-inventory-$$"
cleanup() {
    docker cp "$name:/evidence/." "$out/" >/dev/null 2>&1 || true
    docker rm -f "$name" >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker run -d --name "$name" --privileged --cgroupns=private --network none \
    --tmpfs /run --tmpfs /tmp -e container=docker "$image" >/dev/null
docker inspect "$name" >"$out/container.json"
docker exec "$name" timeout 30 sh -ec 'until systemctl show-environment >/dev/null 2>&1; do sleep .1; done'
docker exec "$name" mkdir /evidence
docker cp "$root/native.py" "$name:/native.py"
docker exec "$name" python3 /native.py
