#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

source "$ROOT_DIR/packaging/lib/build-resources.sh"

fail() {
    echo "build resource test failed: $1" >&2
    exit 1
}

fic_detect_cpu_count() {
    printf '12\n'
}

fic_detect_available_memory_mb() {
    printf '8192\n'
}

unset BUILD_JOBS
unset FIC_BUILD_MEMORY_BUDGET_MB
unset FIC_DETECTED_AVAILABLE_MEMORY_MB
unset FIC_DETECTED_CPUS
unset FIC_BUILD_RESOURCES_CONFIGURED
unset CONTAINER_CPUS
unset CONTAINER_MEMORY_MB
unset CONTAINER_MEMORY_SWAP_MB

fic_configure_build_resources >/dev/null
[ "$BUILD_JOBS" = "3" ] || fail "expected 3 automatic jobs, got $BUILD_JOBS"
[ "$FIC_BUILD_MEMORY_BUDGET_MB" = "6144" ] ||
    fail "expected a 6144 MiB memory budget"

fic_configure_container_resources >/dev/null
[ "$CONTAINER_CPUS" = "3" ] || fail "container CPU limit does not match jobs"
[ "$CONTAINER_MEMORY_MB" = "6144" ] || fail "unexpected container memory limit"
[ "$CONTAINER_MEMORY_SWAP_MB" = "$CONTAINER_MEMORY_MB" ] ||
    fail "container swap must be disabled by default"

[ "${FIC_CONTAINER_BUILD_ARGS[*]}" = \
    "--cpu-period 100000 --cpu-quota 300000 --memory 6144m --memory-swap 6144m" ] ||
    fail "image-build limits are incomplete"

[ "${FIC_CONTAINER_RUN_ARGS[*]}" = \
    "--cpus 3 --memory 6144m --memory-swap 6144m" ] ||
    fail "container-run limits are incomplete"

if (
    unset FIC_BUILD_RESOURCES_CONFIGURED
    BUILD_JOBS=0
    fic_configure_build_resources
) >/dev/null 2>&1; then
    fail "BUILD_JOBS=0 must be rejected"
fi

if (
    unset FIC_BUILD_RESOURCES_CONFIGURED
    BUILD_JOBS=1
    CONTAINER_MEMORY_MB=4096
    CONTAINER_MEMORY_SWAP_MB=2048
    fic_configure_build_resources
    fic_configure_container_resources
) >/dev/null 2>&1; then
    fail "a swap limit below the memory limit must be rejected"
fi

(
    unset BUILD_JOBS
    unset FIC_BUILD_RESOURCES_CONFIGURED
    fic_detect_available_memory_mb() {
        printf '2500\n'
    }
    fic_configure_build_resources >/dev/null 2>&1
    [ "$BUILD_JOBS" = "1" ] &&
        [ "$FIC_BUILD_MEMORY_BUDGET_MB" = "1024" ]
) || fail "low-memory hosts must use one job and the minimum memory budget"

echo "build resource tests passed"
