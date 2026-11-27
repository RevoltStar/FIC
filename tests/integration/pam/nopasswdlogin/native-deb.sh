#!/bin/bash
set -euo pipefail
[[ -f /.dockerenv ]]
driver=$1
auth=$2
work=$(mktemp -d)
journal=$work/journal.json
export LC_ALL=C
dpkg-query -W libpam0g libpam-runtime gdm3 lightdm sddm
groupadd -f nopasswdlogin
useradd -m -G nopasswdlogin ficdirect
useradd -m ficordinary
printf '%s\n' ficdirect:FicNative7-Test ficordinary:FicNative7-Test | chpasswd
services=(gdm-password lightdm sddm)
for s in "${services[@]}"; do
    cp "/etc/pam.d/$s" "$work/$s.stock"
    "$driver" prove "$journal" "$s"
done
cp /etc/pam.d/common-auth "$work/common-auth.initial"
cp /etc/group "$work/group"
cp /etc/gshadow "$work/gshadow"
probe() {
    local service=$1 user=$2 password=$3 expected=$4 prompts=$5 result code=0
    result=$(printf '%s\n-\n' "$password" | "$auth" "$service" "$user") || code=$?
    printf 'AUTH %s %s %s\n' "$service" "$user" "$result"
    [[ $code == "$expected" && $result == *"password_prompts=$prompts "* ]]
}
activate_rules() {
python3 - <<'PY'
import pathlib
import re

for service in ("gdm-password", "lightdm", "sddm"):
    path = pathlib.Path("/etc/pam.d") / service
    content = path.read_text()
    active = r"(?m)^auth\s+sufficient\s+pam_succeed_if\.so user ingroup nopasswdlogin\s*$"
    commented = r"(?m)^#[ \t]*(auth[ \t]+sufficient[ \t]+pam_succeed_if\.so user ingroup nopasswdlogin)[ \t]*$"
    if re.search(active, content):
        continue
    if re.search(commented, content):
        content = re.sub(commented, r"\1", content, count=1)
    else:
        anchor = "@include common-auth"
        assert anchor in content, service
        content = content.replace(anchor, "auth sufficient pam_succeed_if.so user ingroup nopasswdlogin\n" + anchor, 1)
    path.write_text(content)
PY
}

if [[ ${3:-full} == absent-group ]]; then
    activate_rules
    gpasswd -M '' nopasswdlogin
    groupdel nopasswdlogin
    for s in "${services[@]}"; do cp "/etc/pam.d/$s" "$work/$s.absent"; done
    cp /etc/group "$work/group.absent"
    "$driver" apply "$journal"
    for s in "${services[@]}"; do
        for user in ficdirect ficordinary; do
            probe "$s" "$user" wrong 1 1
            probe "$s" "$user" FicNative7-Test 0 1
        done
    done
    "$driver" release "$journal"
    for s in "${services[@]}"; do cmp "$work/$s.absent" "/etc/pam.d/$s"; done
    cmp "$work/group.absent" /etc/group
    echo 'RESULT PASS DEB absent nopasswdlogin group'
    exit
fi
# Real stock files, including Ubuntu 24.04's active LightDM rule.
for s in "${services[@]}"; do
    if grep -Eq '^auth[[:space:]]+sufficient[[:space:]]+pam_succeed_if.so user ingroup nopasswdlogin' "/etc/pam.d/$s"; then
        probe "$s" ficdirect wrong 0 0
    else
        probe "$s" ficdirect wrong 1 1
        probe "$s" ficdirect FicNative7-Test 0 1
    fi
done
"$driver" apply "$journal"
for s in "${services[@]}"; do
    probe "$s" ficdirect wrong 1 1
    probe "$s" ficdirect FicNative7-Test 0 1
    if ! grep -Eq '^auth[[:space:]]+sufficient[[:space:]]+pam_succeed_if.so user ingroup nopasswdlogin' "$work/$s.stock"; then
        cmp "$work/$s.stock" "/etc/pam.d/$s"
    fi
done
"$driver" release "$journal"
for s in "${services[@]}"; do cmp "$work/$s.stock" "/etc/pam.d/$s"; done
cmp "$work/common-auth.initial" /etc/pam.d/common-auth
# Activate exactly the supported bypass, as an administrator might.
activate_rules
for s in "${services[@]}"; do
    cp "/etc/pam.d/$s" "$work/$s.manual"
    probe "$s" ficdirect wrong 0 0
done
"$driver" apply "$journal"
for s in "${services[@]}"; do
    for user in ficdirect ficordinary; do
        probe "$s" "$user" wrong 1 1
        probe "$s" "$user" FicNative7-Test 0 1
    done
done
cp /etc/pam.d/common-auth "$work/common-auth"
pam-auth-update --package
cp /etc/pam.d/common-auth "$work/common-auth.regenerated"
"$driver" apply "$journal"
"$driver" release "$journal"
for s in "${services[@]}"; do cmp "$work/$s.manual" "/etc/pam.d/$s"; done
cmp "$work/common-auth.regenerated" /etc/pam.d/common-auth
cmp "$work/group" /etc/group
cmp "$work/gshadow" /etc/gshadow
gpasswd -M '' nopasswdlogin
groupdel nopasswdlogin
"$driver" apply "$journal"
for s in "${services[@]}"; do
    probe "$s" ficordinary wrong 1 1
    probe "$s" ficordinary FicNative7-Test 0 1
done
"$driver" release "$journal"

# Package reinstall normally preserves a modified conffile.
"$driver" apply "$journal"
for s in "${services[@]}"; do cp "/etc/pam.d/$s" "$work/$s.owned"; done
dpkg -i /native-debs/*.deb
for s in "${services[@]}"; do cmp "$work/$s.owned" "/etc/pam.d/$s"; done
"$driver" release "$journal"
# A real removal must never make the backend recreate missing service files.
# Purge removes conffiles even when the old package was in config-files state.
"$driver" apply "$journal"
apt-get -y --purge remove gdm3 lightdm sddm
"$driver" release "$journal"
for s in "${services[@]}"; do [[ ! -e /etc/pam.d/$s ]]; done
echo 'RESULT PASS DEB stock/manual PAM, native passwords, conffile proof, reinstall and purge'
