#!/usr/bin/env bash
# Existing package-lifecycle native harness, focused on real client packages.
set -euo pipefail
[[ $# == 4 ]] || { echo 'usage: run-client-access.sh IMAGE deb|rpm INPUT_ARTIFACTS DISTRO_TAG' >&2; exit 2; }
image=$1 kind=$2 inputs=$(realpath "$3") row=$4
case "$kind:$row" in deb:debian12|deb:debian13|deb:ubuntu2404|deb:ubuntu2604|rpm:altp11) ;; *) exit 2;; esac
repo=$(cd "$(dirname "$0")/../../.." && pwd)
out="$repo/build-package-lifecycle/client-access-$row"
mkdir -p "$out/packages" "$out/results"
rm -f "$out/results/result.json" "$out/results/access-events.json"
# No host /etc, users, PAM, persistent state, ports, or privileged namespace.
podman run --rm --network none -v "$repo:/src:ro" -v "$inputs:/inputs:ro" \
 -v "$out/packages:/out:rw" "$image" bash \
 /src/tests/integration/package-lifecycle/build-client-access.sh "$kind" /inputs /out "$row" \
 > "$out/build.log" 2>&1
podman run --rm --network none -v "$repo:/src:ro" -v "$out/packages:/packages:ro" \
 -v "$out/results:/out:rw" "$image" python3 \
 /src/tests/integration/package-lifecycle/client_access_native.py "$kind" /packages "$row" \
 > "$out/native.log" 2>&1
cat "$out/results/result.json"
