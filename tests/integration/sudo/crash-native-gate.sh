#!/bin/sh
set -eu
test -f /run/.containerenv
test "$(id -u)" = 0
driver=$1
work=$(mktemp -d /tmp/fic-sudo-crash-XXXXXX)
trap 'rm -rf "$work"' EXIT HUP INT TERM
sha256sum /etc/sudoers > "$work/original"
scenarios=0
for refresh in no yes; do
    for phase in before-prepared prepared file include verified; do
        if [ "$refresh" = yes ]; then
            "$driver" apply sudo_passwd_tries 3
        fi
        code=0
        "$driver" crash-apply sudo_passwd_tries 4 "$phase" || code=$?
        test "$code" = 86
        visudo -c
        "$driver" apply sudo_passwd_tries 4 > "$work/recovered"
        grep '^active-policy-records=1$' "$work/recovered"
        visudo -c
        "$driver" release sudo_passwd_tries
        test ! -e /etc/sudoers.d/99-fic.conf
        sha256sum -c "$work/original"
        scenarios=$((scenarios + 1))
    done
done
for phase in file inert detached deleted; do
    "$driver" apply sudo_passwd_tries 3
    code=0
    "$driver" crash-release sudo_passwd_tries "$phase" || code=$?
    test "$code" = 86
    visudo -c
    "$driver" release sudo_passwd_tries
    test ! -e /etc/sudoers.d/99-fic.conf
    sha256sum -c "$work/original"
    scenarios=$((scenarios + 1))
done
"$driver" apply sudo_passwd_tries 3
"$driver" apply sudo_timeout 5
code=0
"$driver" crash-release sudo_passwd_tries file || code=$?
test "$code" = 86
visudo -c
"$driver" release sudo_passwd_tries
grep '^Defaults timestamp_timeout=5$' /etc/sudoers.d/99-fic.conf
"$driver" apply sudo_timeout 5 > "$work/surviving-owner"
grep '^active-policy-records=1$' "$work/surviving-owner"
"$driver" release sudo_timeout
test ! -e /etc/sudoers.d/99-fic.conf
sha256sum -c "$work/original"
scenarios=$((scenarios + 1))
echo "PASS $scenarios native process-crash recovery boundaries"
