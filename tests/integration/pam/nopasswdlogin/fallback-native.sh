#!/usr/bin/env bash
# Run only inside a disposable ALT test container with the production driver.
set -euo pipefail
test -f /.dockerenv
test "$(id -u)" = 0
driver=$(realpath "$1")
groupadd nopasswdlogin
useradd -M -G nopasswdlogin ficfallback
test ! -e /etc/pam.d/lightdm
work=$(mktemp -d)
other=/etc/pam.d/other
rm -f "$other"
"$driver" apply "$work/journal" lightdm
printf 'auth required pam_deny.so\n' > "$other"
cp "$other" "$work/safe"
"$driver" apply "$work/journal" lightdm
cmp "$other" "$work/safe"
printf 'auth sufficient pam_succeed_if.so user ingroup nopasswdlogin\nauth requisite pam_deny.so\n' > "$other"
cp "$other" "$work/bypass"
python3 - <<'PY'
import ctypes
pam = ctypes.CDLL("libpam.so.0")
class Conversation(ctypes.Structure):
    _fields_ = [("callback", ctypes.c_void_p), ("data", ctypes.c_void_p)]
handle = ctypes.c_void_p()
conversation = Conversation()
assert pam.pam_start(b"lightdm", b"ficfallback",
                     ctypes.byref(conversation), ctypes.byref(handle)) == 0
result = pam.pam_authenticate(handle, 0)
pam.pam_end(handle, result)
assert result == 0, result
print("PASS native Linux-PAM consumes other for absent lightdm")
PY
if "$driver" apply "$work/journal" lightdm; then
    echo 'FAIL: fallback bypass accepted' >&2
    exit 1
fi
cmp "$other" "$work/bypass"
printf '# FIC_PAM_NOPASSWDLOGIN orphan\nauth required pam_deny.so\n' > "$other"
cp "$other" "$work/orphan"
if "$driver" apply "$work/journal" lightdm; then
    echo 'FAIL: fallback orphan accepted' >&2
    exit 1
fi
cmp "$other" "$work/orphan"
test ! -e /etc/pam.d/lightdm
echo 'PASS absent/safe/bypass/orphan fallback, no writes or service creation'
