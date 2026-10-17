#!/usr/bin/env bash
# Only disposable, private-namespace Docker containers. Never mount host /etc,
# /run, /sys/fs/cgroup or the Docker socket into the test container.
set -euo pipefail
if [[ $# != 2 ]]; then
    echo "usage: $0 IMAGE FIC_TARGET_PLATFORM" >&2
    exit 2
fi
image=$1
platform=$2
case "$platform" in debian-12|debian-13|ubuntu-24.04|alt-p11) ;; *) echo "unsupported test platform" >&2; exit 2;; esac
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
build="$repo/build-verified-config/$platform"
mkdir -p "$build"
# Override the image's systemd command while compiling in an unprivileged container.
docker run --rm --network none -v "$repo:/src:ro" -v "$build:/build" "$image" \
    sh -ec 'cmake -S /src/tests/integration/verified_config_service -B /build -DFIC_TARGET_PLATFORM="$1"; cmake --build /build --target verified_config_service_native_tests -j2' sh "$platform"
name="fic-vcsa-native-$platform-$$"
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
# Docker supplies a private mount namespace; --cgroupns=private prevents sharing
# the host cgroup namespace. All fixture state lives in this disposable container.
docker run -d --name "$name" --privileged --cgroupns=private --network none \
    --tmpfs /run --tmpfs /tmp -e container=docker "$image" >/dev/null
docker exec "$name" timeout 45 sh -c 'until systemctl show-environment >/dev/null 2>&1; do sleep 0.1; done'
docker cp "$build/verified_config_service_native_tests" "$name:/usr/local/bin/vcsa-native"
docker exec -e FIC_ACTIVATOR_NATIVE=1 "$name" /usr/local/bin/vcsa-native
