#!/usr/bin/env bash
# Real transaction/journal code, fake commands, disposable /tmp only. No host SSH.
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
engine=${CONTAINER_ENGINE:-docker}
rows=("$@")
((${#rows[@]})) || rows=(debian12 debian13 ubuntu2404 ubuntu2604 alt-p11)
for row in "${rows[@]}"; do
 case "$row" in
  debian12) platform=debian-12;;
  debian13) platform=debian-13;;
  ubuntu2404) platform=ubuntu-24.04;;
  ubuntu2604) platform=ubuntu-26.04;;
  alt-p11) platform=alt-p11;;
  *) echo "Unknown profile: $row" >&2; exit 2;;
 esac
 image=${FIC_SSH_NATIVE_IMAGE:-fic-ssh-audit:$row}
 build="$repo/build-ssh-provenance/$row/build"
 logs="$repo/build-ssh-provenance/$row"
 mkdir -p "$build" "$logs"
 "$engine" run --rm --network none --cap-drop DAC_OVERRIDE --cap-drop DAC_READ_SEARCH \
  -v "$repo:/src:ro" -v "$build:/build" "$image" sh -ec '
   chown 0:0 /build
   trap "chown 1000:1000 /build" EXIT
   cmake -S /src/tests/integration/ssh-provenance -B /build -DFIC_TARGET_PLATFORM="$1"
   cmake --build /build --target ssh_apply_rollback_tests -j4
   ctest --test-dir /build --output-on-failure
   /build/ssh_apply_rollback_tests
   case "$1" in
    debian-12|debian-13)
     FIC_DISPOSABLE_NATIVE=1 sh /src/tests/integration/ssh-provenance/openssh-semantics.sh;;
   esac
  ' sh "$platform" > "$logs/native.log" 2>&1
 tail -12 "$logs/native.log"
done
