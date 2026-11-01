#!/usr/bin/env bash
# Fresh real production package build, bound to sources before any compilation.
set -euo pipefail
[[ $# == 2 ]] || { echo 'usage: build-native.sh IMAGE PLATFORM' >&2; exit 2; }
image=$1 platform=$2
case "$platform" in debian-12|debian-13|ubuntu-24.04|ubuntu-26.04|alt-p11);; *) exit 2;; esac
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
build="$repo/build-sssd-i6/$platform"
mkdir -p "$build"
python3 "$repo/tests/integration/sssd-i6/source-manifest.py" > "$build/source-manifest.json"
rm -f "$build/build-receipt.json"
docker run --rm --network none -v "$repo:/src:ro" -v "$build:/build:rw" "$image" bash -ec '
 cmake -S /src -B /build -DBUILD_TESTING=OFF -DFIC_TARGET_PLATFORM="$1" >/build/i6-configure.log
 cmake --build /build --target clean
 rm -rf /build/lifecycle-packages
 if [[ "$1" == alt-p11 ]]; then
   bash /src/tests/integration/package-lifecycle/build-rpm.sh 0.0.0-alpha
 else
   bash /src/tests/integration/package-lifecycle/build-deb.sh "$1" 0.0.0-alpha
 fi' sh "$platform" > "$build/i6-package-build.log" 2>&1
python3 "$repo/tests/integration/sssd-i6/source-manifest.py" check "$build/source-manifest.json"
python3 - "$build" "$platform" <<'PY'
import hashlib,json,sys
from pathlib import Path
p=Path(sys.argv[1]);packages={f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in sorted((p/'lifecycle-packages').iterdir()) if f.suffix in ('.deb','.rpm')}
assert len(packages)==3,packages
receipt={'platform':sys.argv[2],'exit_code':0,'clean_build':True,'source_sha256':json.loads((p/'source-manifest.json').read_text()),'packages':packages,'symbols_sha256':hashlib.sha256((p/'fic/fic').read_bytes()).hexdigest()}
(p/'build-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
PY
