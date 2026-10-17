#!/usr/bin/env bash
# ONLY disposable Docker; never pass host /etc,/run,cgroups/socket mounts.
set -euo pipefail
if [[ $# != 2 ]]; then echo "usage: $0 IMAGE FIC_TARGET_PLATFORM" >&2; exit 2; fi
image=$1
platform=$2
case "$platform" in debian-12|debian-13|ubuntu-24.04|ubuntu-26.04|alt-p11) ;; *) exit 2;; esac
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../../.." && pwd)
build="$repo/build-environment-file-research/$platform"
mkdir -p "$build"
docker run --rm --network none -v "$repo:/src:ro" -v "$build:/build" "$image" \
 sh -ec 'cmake -S /src/tests/integration/verified_config_service/environment_file_research -B /build -DFIC_TARGET_PLATFORM="$1"; cmake --build /build --target environment_file_research -j2' sh "$platform"
name="fic-env-research-$platform-$$"
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
docker run -d --name "$name" --privileged --cgroupns=private --network none \
 --tmpfs /run --tmpfs /tmp -e container=docker "$image" >/dev/null
docker exec "$name" timeout 45 sh -c 'until systemctl show-environment >/dev/null 2>&1; do sleep 0.1; done'
# Startup probe above is infrastructure readiness; all races use IPC barriers.
# stdin avoids docker cp into a tmpfs hidden by systemd mount setup.
docker exec -i "$name" sh -c 'cat > /usr/local/bin/fic-env-research; chmod 700 /usr/local/bin/fic-env-research' < "$build/environment_file_research"
docker exec -e FIC_ENV_RESEARCH_DISPOSABLE=1 "$name" /usr/local/bin/fic-env-research
