#!/bin/bash
# No host /etc mounts or policy execution. Engines run disposable containers.
set -euo pipefail
repo=$(cd "$(dirname "$0")/../../.." && pwd)
engine=${CONTAINER_ENGINE:-podman}
command -v "$engine" >/dev/null
rows=("$@")
((${#rows[@]})) || rows=(debian12 debian13 ubuntu2404 ubuntu2604 alt-p11)
for row in "${rows[@]}"; do
 case $row in
  debian12) target=debian-12; image=fic-deb-builder:debian12-final;;
  debian13) target=debian-13; image=fic-recovery-builder:debian13;;
  ubuntu2404) target=ubuntu-24.04; image=fic-recovery-builder:ubuntu2404;;
  ubuntu2604) target=ubuntu-26.04; image=fic-recovery-builder:ubuntu2604;;
  alt-p11) target=alt-p11; image=fic-aging-native:alt-p11;;
  *) echo "Unknown row: $row" >&2; exit 2;;
 esac
 image=${FIC_NATIVE_IMAGE:-$image}
 build="$repo/build-password-aging-native/$row"
 mkdir -p "$build"
 "$engine" run --rm --network none -v "$repo:/src:ro" -v "$build:/build" "$image" \
  sh -c 'cmake -S /src/tests/integration/password_aging -B /build -DFIC_TARGET_PLATFORM="$1" && cmake --build /build --target password_aging_native_driver -j2' sh "$target" \
  > "$build/native-build.log" 2>&1
 "$engine" run --rm --network none -v "$repo:/src:ro" -v "$build:/build" "$image" \
  python3 /src/tests/integration/password_aging/native-gate.py.in /build/password_aging_native_driver "$row" \
  > "$build/native-gate.log" 2>&1
 tail -1 "$build/native-gate.log"
done
