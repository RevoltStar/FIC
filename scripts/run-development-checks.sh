#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "Usage: $0 {fast|full}" >&2
}

if [[ "$#" -ne 1 ]]; then
    usage
    exit 2
fi

check_set="$1"
case "$check_set" in
    fast|full)
        ;;
    *)
        usage
        exit 2
        ;;
esac

repository_root="$(git rev-parse --show-toplevel)"
configured_build_dir="${FIC_BUILD_DIR:-build-check}"
if [[ "$configured_build_dir" = /* ]]; then
    build_dir="$configured_build_dir"
else
    build_dir="$repository_root/$configured_build_dir"
fi

cache_file="$build_dir/CMakeCache.txt"
if [[ ! -f "$cache_file" ]]; then
    cat >&2 <<EOF
[FIC checks] Build directory is not configured: $build_dir
Configure it once before running hooks, for example:
  cmake -S "$repository_root" -B "$build_dir" -DFIC_TARGET_PLATFORM=ubuntu-24.04
Replace ubuntu-24.04 with the FIC target platform used by your checkout.
You may select another directory with FIC_BUILD_DIR=/path/to/build.
EOF
    exit 1
fi

cache_source="$(sed -n 's/^CMAKE_HOME_DIRECTORY:INTERNAL=//p' "$cache_file")"
if [[ "$cache_source" != "$repository_root" ]]; then
    cat >&2 <<EOF
[FIC checks] $build_dir belongs to a different source tree:
  $cache_source
Select a correctly configured directory through FIC_BUILD_DIR.
EOF
    exit 1
fi

echo "[FIC checks] Building project"
cmake --build "$build_dir" --parallel "${FIC_BUILD_JOBS:-2}"

if [[ "$check_set" == "fast" ]]; then
    echo "[FIC checks] Running fast unit and static tests"
    ctest --test-dir "$build_dir" \
        -L '^(unit|static)$' \
        --output-on-failure
else
    echo "[FIC checks] Running the complete non-root test suite"
    ctest --test-dir "$build_dir" \
        -LE '^root$' \
        --output-on-failure
fi
