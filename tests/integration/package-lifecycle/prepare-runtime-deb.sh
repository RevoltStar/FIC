#!/usr/bin/env bash
# Networked preparation only: download Depends closure; never run FIC here.
set -euo pipefail
[[ $# == 3 ]] || { echo 'usage: prepare-runtime-deb.sh BASE PACKAGE_DIRECTORY OUTPUT_IMAGE' >&2; exit 2; }
base=$1 packages=$(realpath "$2") image=$3
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
context=$(mktemp -d /tmp/fic-runtime-deb-context.XXXXXX)
trap 'rm -rf "$context"' EXIT
mkdir "$context/debs"
cp "$repo/tests/integration/package-lifecycle/runtime-init.sh" "$context/runtime-init.sh"
shopt -s nullglob
for name in fic fic-cli fic-dick; do
    found=("$packages/${name}_"*.deb)
    [[ ${#found[@]} == 1 ]] || { echo "Expected one current $name DEB in $packages" >&2; exit 1; }
    cp -- "${found[0]}" "$context/debs/"
done
docker build --build-arg "BASE=$base" -f "$repo/tests/integration/package-lifecycle/Dockerfile.runtime-deb" -t "$image" "$context"
