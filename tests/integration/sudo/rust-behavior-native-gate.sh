#!/bin/sh
set -eu
test -f /run/.containerenv
test "$(id -u)" = 0
driver=$1
sudo --version | head -1 | grep '^sudo-rs '
work=$(mktemp -d /tmp/fic-rust-behavior-XXXXXX)
trap 'rm -rf "$work"' EXIT HUP INT TERM
sha256sum /etc/sudoers > "$work/original"
useradd -m fic-rust-behavior
# Disposable fixture credential; no host account or PAM files are mounted.
printf 'fic-rust-behavior:fic-native-test-password\n' | chpasswd
grant=/etc/sudoers.d/97-fic-rust-behavior
printf 'fic-rust-behavior ALL=(root) /usr/bin/env, /usr/bin/true\n' > "$grant"
chmod 0440 "$grant"

"$driver" apply sudo_env_reset ENABLE > "$work/env-record"
grep '^active-policy-records=0$' "$work/env-record"
"$driver" apply sudo_exempt_group_disable DISABLE > "$work/exempt-record"
grep '^active-policy-records=0$' "$work/exempt-record"
"$driver" apply sudo_securepath /usr/sbin:/usr/bin:/sbin:/bin
runuser -u fic-rust-behavior -- sh -ec \
    'printf "fic-native-test-password\n" | env FIC_NATIVE_SECRET=hidden sudo -S /usr/bin/env' \
    > "$work/environment" 2> "$work/authentication"
grep '^PATH=/usr/sbin:/usr/bin:/sbin:/bin$' "$work/environment"
if grep '^FIC_NATIVE_SECRET=' "$work/environment"; then
    echo 'FAIL unconditional env_reset leaked fixture variable'
    exit 1
fi
echo 'PASS native secure_path and unconditional env_reset behavior'

printf 'Defaults secure_path=/usr/bin:/bin\n' > /etc/sudoers.d/98-fic-rust-path
chmod 0440 /etc/sudoers.d/98-fic-rust-path
sed '/^#@FIC_INCLUDE_BEGIN$/,$d' /etc/sudoers > "$work/prefix"
cat "$work/prefix" > /etc/sudoers
sudo -n /usr/bin/env > "$work/ignored-conf"
grep '^PATH=/usr/bin:/bin$' "$work/ignored-conf"
printf '#@FIC_INCLUDE_BEGIN\n@include /etc/sudoers.d/99-fic.conf\n#@FIC_INCLUDE_END\n' >> /etc/sudoers
sudo -n /usr/bin/env > "$work/explicit-conf"
grep '^PATH=/usr/sbin:/usr/bin:/sbin:/bin$' "$work/explicit-conf"
rm /etc/sudoers.d/98-fic-rust-path
echo 'PASS native .conf exclusion and explicit EOF include precedence'

"$driver" apply sudo_passwd_tries 3
if runuser -u fic-rust-behavior -- sh -ec \
    'sudo -k; printf "wrong\nwrong\nwrong\nwrong\n" | sudo -S -p FIC_NATIVE_PROMPT /usr/bin/true' \
    > "$work/attempts-out" 2> "$work/attempts-error"; then
    echo 'FAIL wrong passwords authorized a command'
    exit 1
fi
test "$(grep -o FIC_NATIVE_PROMPT "$work/attempts-error" | wc -l)" = 3
echo 'PASS passwd_tries enforces three native authentication attempts'
"$driver" apply sudo_passwd_tries 4
if runuser -u fic-rust-behavior -- sh -ec \
    'sudo -k; printf "wrong\nwrong\nwrong\nwrong\nwrong\n" | sudo -S -p FIC_NATIVE_PROMPT /usr/bin/true' \
    > "$work/refreshed-out" 2> "$work/refreshed-error"; then
    echo 'FAIL refreshed passwd_tries authorized a wrong password'
    exit 1
fi
test "$(grep -o FIC_NATIVE_PROMPT "$work/refreshed-error" | wc -l)" = 4
echo 'PASS native passwd_tries value refresh'

"$driver" apply sudo_timeout 10
runuser -u fic-rust-behavior -- sh -ec \
    'sudo -k; printf "fic-native-test-password\n" | sudo -S /usr/bin/true; sudo -n /usr/bin/true'
"$driver" apply sudo_timeout 0
runuser -u fic-rust-behavior -- sh -ec \
    'sudo -k; printf "fic-native-test-password\n" | sudo -S /usr/bin/true; if sudo -n /usr/bin/true; then exit 1; fi'
echo 'PASS timestamp_timeout changes native authentication cache behavior'
printf 'Defaults:fic-rust-behavior timestamp_timeout=0\n' >> "$grant"
"$driver" apply sudo_timeout 10
runuser -u fic-rust-behavior -- sh -ec \
    'sudo -k; printf "fic-native-test-password\n" | sudo -S /usr/bin/true; sudo -n /usr/bin/true'
grep '^Defaults:fic-rust-behavior timestamp_timeout=0$' "$grant"
# This tested sudo-rs version applies matching Defaults in source order:
# unlike classic, its later global entry wins over this earlier user entry.
echo 'PASS sudo-rs later global timeout wins while foreign contextual bytes remain intact'
"$driver" apply sudo_env_reset ENABLE
"$driver" apply sudo_exempt_group_disable DISABLE
"$driver" apply sudo_securepath /usr/sbin:/usr/bin:/sbin:/bin
"$driver" apply sudo_passwd_tries 4
"$driver" apply sudo_timeout 10
echo 'PASS native sudo-rs repeated global apply'
printf '# foreign after FIC block\n' >> /etc/sudoers
sha256sum /etc/sudoers > "$work/drift"
if "$driver" apply sudo_timeout 10; then
    echo 'FAIL sudo-rs accepted foreign suffix after owned EOF block'
    exit 1
fi
sha256sum -c "$work/drift"
sed '$d' /etc/sudoers > "$work/restored-fixture"
cat "$work/restored-fixture" > /etc/sudoers
echo 'PASS native sudo-rs EOF drift refusal preserves foreign bytes'
for policy in sudo_securepath sudo_passwd_tries sudo_timeout; do
    "$driver" release "$policy"
done
test ! -e /etc/sudoers.d/99-fic.conf
sha256sum -c "$work/original"
visudo -c
echo 'PASS native sudo-rs configurable Defaults apply and rollback'
