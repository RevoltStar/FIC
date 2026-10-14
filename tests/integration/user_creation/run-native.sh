#!/bin/bash
# Uses existing native builders; no host policy apply, no host /etc mounts.
set -euo pipefail
repo=$(cd "$(dirname "$0")/../../.." && pwd)
rows=("$@")
((${#rows[@]})) || rows=(debian12 debian13 ubuntu2404 ubuntu2604 alt-p11)
for row in "${rows[@]}"; do
 case $row in
  debian12) target=debian-12; builder=localhost/fic-quarantine-test:debian12; runtime=localhost/fic-sudo-native-runtime:debian12;;
  debian13) target=debian-13; builder=localhost/fic-sudo-native:debian13; runtime=localhost/fic-user-creation-native-runtime:debian13;;
  ubuntu2404) target=ubuntu-24.04; builder=localhost/fic-sudo-native:ubuntu2404; runtime=localhost/fic-user-creation-native-runtime:ubuntu2404;;
  ubuntu2604) target=ubuntu-26.04; builder=localhost/fic-sudo-native:ubuntu2604; runtime=localhost/fic-user-creation-native-runtime:ubuntu2604;;
  alt-p11) target=alt-p11; builder=localhost/fic-sudo-native:alt-p11; runtime=localhost/fic-sudo-native-runtime:alt-p11;;
  *) echo "Unknown row: $row" >&2; exit 2;;
 esac
 build="$repo/build-user-creation-native/$row"
 mkdir -p "$build"
 podman run --rm --network none --entrypoint /bin/sh \
  -v "$repo:/src:ro" -v "$build:/build:rw" "$builder" \
  -c "cmake -S /src/tests/integration/user_creation -B /build -DFIC_TARGET_PLATFORM=$target > /build/configure.log 2>&1 && cmake --build /build -j2 > /build/build.log 2>&1" \
  > "$build/container-build.log" 2>&1
 podman run --rm --network none --entrypoint /bin/bash \
  -v "$repo:/src:ro" -v "$build:/build:rw" "$runtime" \
  /src/tests/integration/user_creation/native-gate.sh /build/user_creation_native_driver "$row" \
  > "$build/native-gate.log" 2>&1
 tail -1 "$build/native-gate.log"
done
