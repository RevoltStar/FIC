#!/bin/sh
set -eu
test -f /run/.containerenv
test "$(id -u)" = 0
driver=$1
work=$(mktemp -d /tmp/fic-provider-transition-XXXXXX)
trap 'rm -rf "$work"' EXIT HUP INT TERM
sudo --version | head -1 | grep '^sudo-rs '
sha256sum /etc/sudoers > "$work/original"

# Selector changes are test operations confined to this disposable container.
update-alternatives --set sudo /usr/bin/sudo.ws
"$driver" apply sudo_env_reset ENABLE > "$work/classic-env"
grep '^active-policy-records=1$' "$work/classic-env"
"$driver" apply sudo_exempt_group_disable DISABLE
"$driver" apply sudo_passwd_tries 3
grep '^Defaults !exempt_group$' /etc/sudoers.d/99-fic.conf
visudo -c

update-alternatives --set sudo /usr/lib/cargo/bin/sudo
"$driver" apply sudo_env_reset ENABLE > "$work/rust-env"
grep '^active-policy-records=0$' "$work/rust-env"
"$driver" apply sudo_exempt_group_disable DISABLE > "$work/rust-exempt"
grep '^active-policy-records=0$' "$work/rust-exempt"
if grep -E '^Defaults (!?env_reset|!?exempt_group)' /etc/sudoers.d/99-fic.conf; then
    echo 'FAIL construction guarantee retained a fictitious owned setting'
    exit 1
fi
grep '^Defaults passwd_tries=3$' /etc/sudoers.d/99-fic.conf
visudo -c
"$driver" release sudo_passwd_tries
test ! -e /etc/sudoers.d/99-fic.conf
sha256sum -c "$work/original"
echo 'PASS classic ownership safely released after transition to sudo-rs'

update-alternatives --set sudo /usr/bin/sudo.ws
"$driver" apply sudo_env_reset ENABLE > "$work/classic-again"
grep '^active-policy-records=1$' "$work/classic-again"
grep '^Defaults env_reset$' /etc/sudoers.d/99-fic.conf
"$driver" release sudo_env_reset
test ! -e /etc/sudoers.d/99-fic.conf
sha256sum -c "$work/original"
visudo -c
echo 'PASS transition back to classic creates and releases real ownership'
