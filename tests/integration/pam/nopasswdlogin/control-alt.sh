#!/bin/bash
set -euo pipefail
[[ -f /.dockerenv ]]
driver=$1
auth=$2
work=$(mktemp -d)
journal=$work/journal
groupadd -f nopasswdlogin
useradd -m -G nopasswdlogin ficcontrol
echo 'ficcontrol:FicNative7-Test' | chpasswd
cp /etc/pam.d/lightdm "$work/lightdm"
initial=$(control system-auth)
"$driver" apply "$journal"
for s in gdm-password gdm-fingerprint gdm-smartcard lightdm sddm; do
    sha256sum "/etc/pam.d/$s"
done > "$work/checksums"
for mode in $(control system-auth list); do
    control system-auth "$mode"
    [[ $(control system-auth) == "$mode" ]]
    if [[ $mode == fprintd ]]; then
        # Existing trusted aliases intentionally exclude this topology.
        if "$driver" apply "$journal"; then exit 1; fi
        for s in gdm-password gdm-fingerprint gdm-smartcard lightdm sddm; do sha256sum "/etc/pam.d/$s"; done | cmp "$work/checksums" -
        echo 'PASS unsupported fprintd alias refused without changing ownership'
        continue
    fi
    "$driver" apply "$journal"
    for s in gdm-password gdm-fingerprint gdm-smartcard lightdm sddm; do sha256sum "/etc/pam.d/$s"; done | cmp "$work/checksums" -
    for s in gdm-password lightdm; do
        code=0
        result=$(printf 'wrong\n-\n' | "$auth" "$s" ficcontrol) || code=$?
        printf 'MODE %s %s %s\n' "$mode" "$s" "$result"
        [[ $code == 1 ]]
    done
done
control system-auth "$initial"
printf '# administrator\n' > "$work/changed"
cat /etc/pam.d/lightdm >> "$work/changed"
cp "$work/changed" /etc/pam.d/lightdm.tmp
mv /etc/pam.d/lightdm.tmp /etc/pam.d/lightdm
"$driver" apply "$journal"
"$driver" release "$journal"
{ printf '# administrator\n'; cat "$work/lightdm"; } | cmp /etc/pam.d/lightdm -
echo 'RESULT PASS ALT control modes and administrative inode replacement'
