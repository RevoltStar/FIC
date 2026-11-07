#!/usr/bin/env bash
# Narrow native consumer check of the existing C2 initial-producer semantics.
# Disposable Debian/Ubuntu container only; this is NOT a FIC policy E2E gate.
set -euo pipefail
[[ -f /.dockerenv && $EUID == 0 ]] || exit 97
repo=${GATE_REPO:-/src}
cc "$repo/tests/integration/pam-c2/fic_pam_probe.c" -lpam -o /tmp/fic-i1-pam-probe
useradd -M fic_i1_probe
printf '%s\n' 'password requisite pam_pwhistory.so remember=3 enforce_for_root' \
 'password required pam_unix.so use_authtok yescrypt' > /etc/pam.d/passwd
printf '%s\n' 'fic_i1_probe:Initial!2026#NativeX9' | chpasswd
FIC_GATE_PW='Next!2026#NativeX9A' /tmp/fic-i1-pam-probe fic_i1_probe
FIC_GATE_PW='Other!2026#NativeX9B' /tmp/fic-i1-pam-probe fic_i1_probe
if FIC_GATE_PW='Next!2026#NativeX9A' /tmp/fic-i1-pam-probe fic_i1_probe; then
 echo 'FAIL native history reuse unexpectedly accepted'; exit 1
fi
echo 'PASS native pwhistory initial producer: two changes succeed; reuse rejected'
dpkg-query -W libpam0g libpam-modules
