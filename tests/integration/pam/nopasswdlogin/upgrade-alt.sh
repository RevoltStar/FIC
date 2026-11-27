#!/bin/bash
set -euo pipefail
[[ -f /.dockerenv ]]
driver=$1
auth=$2
artifacts=${driver%/*}
work=$(mktemp -d)
export LC_ALL=C
groupadd -f nopasswdlogin
useradd -m -G nopasswdlogin ficupgrade
echo 'ficupgrade:FicNative7-Test' | chpasswd
rpm -i "$artifacts"/rpms-old/libaccountsservice-*.rpm
mapfile -t old < <(find "$artifacts/rpms-old" -maxdepth 1 -type f -name 'gdm-*.rpm' | sort)
mapfile -t new < <(find "$artifacts/rpms" -maxdepth 1 -type f -name 'gdm-*.rpm' | sort)
probe() {
    local expected=$1 output code=0
    output=$(printf 'wrong\n-\n' | "$auth" gdm-password ficupgrade) || code=$?
    printf 'AUTH %s\n' "$output"
    [[ $code == "$expected" ]]
}
for scenario in release-before-reapply release-after-reapply; do
    journal="$work/$scenario.json"
    rpm -U --oldpackage "${old[@]}"
    rpm -q gdm gdm-data
    "$driver" prove "$journal" gdm-password
    "$driver" apply "$journal" gdm-password
    probe 1
    rpm -U "${new[@]}"
    rpm -q gdm gdm-data
    [[ -f /etc/pam.d/gdm-password.rpmsave ]]
    grep -F 'FIC_PAM_NOPASSWDLOGIN' /etc/pam.d/gdm-password.rpmsave
    probe 0
    cp /etc/pam.d/gdm-password "$work/new-stock"
    "$driver" prove "$journal" gdm-password
    if [[ $scenario == release-after-reapply ]]; then
        "$driver" apply "$journal" gdm-password
        probe 1
    fi
    "$driver" release "$journal" gdm-password
    cmp "$work/new-stock" /etc/pam.d/gdm-password
    probe 0
    echo "PASS $scenario"
done
# Actual reinstall preserves the owned modified conffile at the same version.
journal="$work/reinstall.json"
"$driver" apply "$journal" gdm-password
cp /etc/pam.d/gdm-password "$work/owned"
rpm -U --replacepkgs "${new[@]}"
cmp "$work/owned" /etc/pam.d/gdm-password
"$driver" release "$journal" gdm-password
cmp "$work/new-stock" /etc/pam.d/gdm-password
# Exercise the actual package's dependency-complete removal.
"$driver" apply "$journal" gdm-password
rpm -e gdm gdm-data gnome-shell
"$driver" release "$journal" gdm-password
[[ ! -e /etc/pam.d/gdm-password && -f /etc/pam.d/gdm-password.rpmsave ]]
echo 'RESULT PASS GDM official upgrade, reapply, no-write stock release, reinstall and removal'
