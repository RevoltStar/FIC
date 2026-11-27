#!/bin/bash
set -euo pipefail
[[ -f /.dockerenv ]]
driver=$1
auth=$2
work=$(mktemp -d)
journal=$work/journal.json
export LC_ALL=C
rpm -q pam pam-config libnss-role gdm gdm-data lightdm sddm
groupadd -f nopasswdlogin
groupadd ficnativeinherited
useradd -m -G nopasswdlogin ficdirect
useradd -m -g ficnativeinherited ficinherited
useradd -m ficordinary
printf '%s\n' ficdirect:FicNative7-Test ficinherited:FicNative7-Test ficordinary:FicNative7-Test | chpasswd
sed -i 's/^group:.*/group: files [SUCCESS=merge] systemd role/; /^initgroups:/d' /etc/nsswitch.conf
echo 'ficnativeinherited:nopasswdlogin' >> /etc/role
id ficdirect
id ficinherited
id -nG ficinherited | tr ' ' '\n' | grep -qx nopasswdlogin
cp /etc/group "$work/group"
cp /etc/gshadow "$work/gshadow"
cp /etc/role "$work/role"
for service in emptty plasmalogin; do
    package="${driver%/*}/rpms/$service.rpm"
    rpm -qp --qf '%{NAME} %{VERSION}-%{RELEASE}\n' "$package"
    sha256sum "$package"
    mkdir "$work/$service-payload"
    (cd "$work/$service-payload"; rpm2cpio "$package" | cpio -id --quiet)
    cp "$work/$service-payload/etc/pam.d/$service" "/etc/pam.d/$service"
done
services=(gdm-password gdm-fingerprint gdm-smartcard lightdm sddm plasmalogin emptty)
for s in "${services[@]}"; do cp "/etc/pam.d/$s" "$work/$s"; done

probe() {
    local service=$1 user=$2 password=$3 expected=$4 prompts=$5 result code=0
    result=$(printf '%s\n-\n' "$password" | "$auth" "$service" "$user") || code=$?
    printf 'AUTH %s %s %s\n' "$service" "$user" "$result"
    [[ $code == "$expected" && ( $prompts == any || $result == *"password_prompts=$prompts "* ) ]]
}
baseline() {
    for s in "${services[@]}"; do
        probe "$s" ficdirect wrong 0 0
        probe "$s" ficinherited wrong 0 0
    done
}
restricted() {
    for s in gdm-password lightdm sddm plasmalogin emptty; do
        for user in ficdirect ficinherited ficordinary; do
            probe "$s" "$user" wrong 1 1
            probe "$s" "$user" FicNative7-Test 0 1
        done
    done
    for s in gdm-fingerprint gdm-smartcard; do
        probe "$s" ficdirect wrong 1 any
        probe "$s" ficinherited wrong 1 any
    done
}
baseline
"$driver" prove "$journal" gdm-password
"$driver" prove "$journal" lightdm
"$driver" prove "$journal" sddm
"$driver" apply "$journal"
restricted
for s in "${services[@]}"; do stat -c '%d:%i' "/etc/pam.d/$s"; done > "$work/inodes"
"$driver" apply "$journal"
for s in "${services[@]}"; do stat -c '%d:%i' "/etc/pam.d/$s"; done | cmp "$work/inodes" -
"$driver" release "$journal"
baseline
for s in "${services[@]}"; do cmp "$work/$s" "/etc/pam.d/$s"; done
for phase in before after; do
    code=0
    "$driver" "crash-$phase" "$journal" lightdm || code=$?
    [[ $code == 71 || $code == 72 ]]
    "$driver" apply "$journal" lightdm
    probe lightdm ficinherited wrong 1 1
    "$driver" release "$journal" lightdm
    cmp "$work/lightdm" /etc/pam.d/lightdm
done
cmp "$work/group" /etc/group
cmp "$work/gshadow" /etc/gshadow
cmp "$work/role" /etc/role
# A real but unsupported group-list bypass must never report compliance.
for topology in direct included; do
    printf 'auth sufficient pam_succeed_if.so user ingroup nopasswdlogin:wheel\nauth required pam_unix.so\n' > /etc/pam.d/lightdm
    if [[ $topology == included ]]; then
        mv /etc/pam.d/lightdm /etc/pam.d/fic-native-unsupported
        printf 'auth include fic-native-unsupported\n' > /etc/pam.d/lightdm
    fi
    cp /etc/pam.d/lightdm "$work/unsupported"
    probe lightdm ficdirect wrong 0 0
    if "$driver" apply "$work/unsupported-$topology.json" lightdm; then exit 1; fi
    cmp "$work/unsupported" /etc/pam.d/lightdm
    probe lightdm ficdirect wrong 0 0
    cp "$work/lightdm" /etc/pam.d/lightdm
done
rm /etc/pam.d/fic-native-unsupported
# The caller has no supplementary membership when the group is absent.
gpasswd -M '' nopasswdlogin
groupdel nopasswdlogin
"$driver" apply "$journal"
probe lightdm ficordinary wrong 1 1
probe lightdm ficordinary FicNative7-Test 0 1
"$driver" release "$journal"
for s in "${services[@]}"; do cmp "$work/$s" "/etc/pam.d/$s"; done
echo 'RESULT PASS ALT stock PAM, RPM metadata, NSS inheritance and crash recovery'
