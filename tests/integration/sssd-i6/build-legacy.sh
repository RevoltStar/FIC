#!/usr/bin/env bash
# Historical real packages from the exact accepted I5 commit; no source edits.
set -euo pipefail
[[ $# == 2 ]] || { echo 'usage: build-legacy.sh IMAGE PLATFORM' >&2; exit 2; }
image=$1 platform=$2
case "$platform" in debian-12|debian-13|ubuntu-24.04|ubuntu-26.04|alt-p11);; *) exit 2;; esac
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
base=4717cfd4af6df9297b1a6234759258a415dcea34
source_dir=$(mktemp -d /tmp/fic-i6-legacy-XXXXXX)
trap 'rm -rf -- "$source_dir"' EXIT
git -C "$repo" archive "$base" | tar -x -C "$source_dir"
build="$repo/build-sssd-i6/legacy-$platform";mkdir -p "$build"
rm -f "$build/legacy-build-receipt.json"
docker run --rm --network none -v "$source_dir:/src:ro" -v "$build:/build:rw" "$image" bash -ec '
 cmake -S /src -B /build -DBUILD_TESTING=OFF -DFIC_TARGET_PLATFORM="$1" >/build/configure.log
 cmake --build /build --target clean
 rm -rf /build/lifecycle-packages
 if [[ "$1" == alt-p11 ]]; then bash /src/tests/integration/package-lifecycle/build-rpm.sh 0.0.0-a;
 else bash /src/tests/integration/package-lifecycle/build-deb.sh "$1" 0.0.0-a; fi' sh "$platform" > "$build/package-build.log" 2>&1
python3 - "$build" "$platform" "$base" "$(git -C "$repo" rev-parse "$base^{tree}")" <<'PY'
import hashlib,json,sys
from pathlib import Path
p=Path(sys.argv[1]);packages={f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in sorted((p/'lifecycle-packages').iterdir()) if f.suffix in ('.deb','.rpm')}
assert len(packages)==3,packages
(p/'legacy-build-receipt.json').write_text(json.dumps({'platform':sys.argv[2],'base':sys.argv[3],'source_tree':sys.argv[4],
 'exit_code':0,'clean_build':True,'product_version':'0.0.0-a','packages':packages,'symbols_sha256':hashlib.sha256((p/'fic/fic').read_bytes()).hexdigest()},indent=2)+'\n')
PY
