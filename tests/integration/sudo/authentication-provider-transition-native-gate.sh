#!/bin/sh
set -eu
driver=$1
work=/var/lib/fic-auth-transition-gate
mkdir -p "$work"
update-alternatives --set sudo /usr/bin/sudo.ws
useradd -m fic-auth-transition
printf 'fic-auth-transition:FicNative1!\n' | chpasswd
source=/etc/sudoers.d/98-fic-auth-transition
printf 'fic-auth-transition ALL=(root) NOPASSWD: /usr/bin/printf allowed argument, \\\n    /usr/bin/true\n' > "$source"
chmod 0440 "$source"
cp "$source" "$work/original"
"$driver" intent sudo_disable_scoped_defaults DISABLE
"$driver" apply sudo_exempt_group_disable DISABLE
"$driver" apply sudo_require_authentication ENABLE
cp "$source" "$work/applied"
prove_auth() {
    if runuser -u fic-auth-transition -- sudo -k -n /usr/bin/printf allowed argument; then echo 'FAIL authentication lost on provider switch'; exit 1; fi
    printf 'FicNative1!\n' | runuser -u fic-auth-transition -- sudo -k -S /usr/bin/printf allowed argument > "$work/allowed"
    grep -qx allowed "$work/allowed"
    if printf 'FicNative1!\n' | runuser -u fic-auth-transition -- sudo -k -S /usr/bin/printf forbidden; then echo 'FAIL argument permissions broadened on provider switch'; exit 1; fi
}
prove_auth
update-alternatives --set sudo /usr/lib/cargo/bin/sudo
# Independently retire classic exemption ownership using its own policy.
"$driver" apply sudo_exempt_group_disable DISABLE
"$driver" apply sudo_require_authentication ENABLE
cmp "$source" "$work/applied"
prove_auth
"$driver" release sudo_require_authentication
cmp "$source" "$work/original"
echo 'PASS classic authentication ownership safely released by active sudo-rs'
"$driver" apply sudo_require_authentication ENABLE
update-alternatives --set sudo /usr/bin/sudo.ws
"$driver" apply sudo_exempt_group_disable DISABLE
"$driver" apply sudo_require_authentication ENABLE
prove_auth
"$driver" release sudo_require_authentication
cmp "$source" "$work/original"
"$driver" release sudo_exempt_group_disable
visudo -c
echo 'PASS sudo-rs authentication ownership safely released by active classic'
