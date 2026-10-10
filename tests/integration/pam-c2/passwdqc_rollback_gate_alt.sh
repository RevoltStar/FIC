#!/usr/bin/env bash
# Run inside a disposable ALT builder with libpasswdqc-devel installed.
set -euo pipefail
[[ -f /.dockerenv && $(id -u) = 0 ]] || { echo 'NOT VERIFIED: disposable root Docker container required' >&2; exit 97; }
source /etc/os-release
[[ $ID = altlinux ]] || { echo 'NOT VERIFIED: native ALT required' >&2; exit 97; }
REPO=${REPO:-/src}
BUILD=${BUILD:-/tmp/fic-passwdqc-build}
EVID=${EVID:?Set EVID to a mounted evidence directory}
mkdir -p "$EVID"
rpm -q libpasswdqc-devel > "$EVID/native-header-package.txt" || { echo 'NOT VERIFIED: install native libpasswdqc-devel in builder' >&2; exit 97; }
cmake -S "$REPO" -B "$BUILD" -DFIC_TARGET_PLATFORM=alt-p11 -DCMAKE_BUILD_TYPE=Release > "$EVID/configure.log" 2>&1
cmake --build "$BUILD" --target fic-pam-provider-rollback-driver -j2 > "$EVID/build.log" 2>&1
cp "$BUILD/tests/fic-pam-provider-rollback-driver" "$EVID/driver"
cc -Wall -Werror "$REPO/tests/integration/pam-c2/passwdqc_native_probe.c" -lpasswdqc -o "$EVID/native-probe" > "$EVID/native-build.log" 2>&1
python3 "$REPO/tests/integration/pam-c2/passwdqc_rollback_gate_alt.py" "$EVID/driver" "$EVID/native-probe" "$EVID/builder" > "$EVID/gate.log" 2>&1
