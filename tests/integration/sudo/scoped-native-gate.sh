#!/bin/sh
set -eu
test -f /run/.containerenv
test "$(id -u)" = 0
driver=$1
work=$(mktemp -d /tmp/fic-scoped-native-XXXXXX)
trap 'rm -rf "$work"' EXIT HUP INT TERM
mode=$(stat -c '%a' /etc/sudoers)
rust_provider=no
if sudo --version | head -1 | grep '^sudo-rs '; then rust_provider=yes; fi
useradd -m fic-scoped-native
if command -v control >/dev/null 2>&1; then
    control sudo wheelonly
    usermod -a -G wheel fic-scoped-native
fi
source=/etc/sudoers.d/98-fic-scoped-native
test ! -e "$source"
printf '# foreign scoped fixture\r\nDefaults:fic-scoped-native passwd_tries=5\nDefaults@ALL timestamp_timeout=0\nDefaults>root secure_path=/usr/bin:/bin\nDefaults!/usr/bin/env !env_reset\nfic-scoped-native ALL=(root) NOPASSWD: /usr/bin/env, /usr/bin/true, /usr/bin/printf allowed argument' > "$source"
chmod "$mode" "$source"
if [ "$rust_provider" = yes ]; then
    # This native provider rejects an unterminated rule. Prove refusal and
    # preservation before choosing a valid LF-terminated positive fixture.
    sha256sum "$source" > "$work/unsupported-terminator"
    if visudo -c || "$driver" apply sudo_disable_scoped_defaults ENABLE; then
        echo 'FAIL sudo-rs accepted an invalid unterminated source'
        exit 1
    fi
    sha256sum -c "$work/unsupported-terminator"
    test ! -e /etc/sudoers.d/99-fic.conf
    printf '\n' >> "$source"
    echo 'PASS sudo-rs rejects unterminated rule without mutation'
fi
sha256sum "$source" > "$work/source-original"
sha256sum /etc/sudoers > "$work/main-original"
visudo -c
apply_globals() {
    "$driver" apply sudo_env_reset ENABLE
    "$driver" apply sudo_passwd_tries 3
    "$driver" apply sudo_securepath /usr/sbin:/usr/bin:/sbin:/bin
    "$driver" apply sudo_timeout 10
    "$driver" apply sudo_exempt_group_disable DISABLE
}
release_globals() {
    for policy in sudo_env_reset sudo_securepath sudo_timeout sudo_passwd_tries sudo_exempt_group_disable; do
        "$driver" release "$policy"
    done
}
prove_permissions() {
    runuser -u fic-scoped-native -- sudo -n /usr/bin/true
    runuser -u fic-scoped-native -- sudo -n /usr/bin/printf allowed argument > "$work/allowed"
    grep -qx allowed "$work/allowed"
    if runuser -u fic-scoped-native -- sudo -n /usr/bin/printf forbidden > "$work/forbidden" 2>&1; then
        echo 'FAIL scoped mutation broadened command argument permissions'
        exit 1
    fi
}
for apply_order in global-first scoped-first; do
    for release_order in global-first scoped-first; do
        prove_permissions
        if [ "$apply_order" = global-first ]; then
            apply_globals
            sha256sum /etc/sudoers.d/99-fic.conf > "$work/global-original"
            "$driver" apply sudo_disable_scoped_defaults ENABLE
            sha256sum -c "$work/global-original"
        else
            "$driver" apply sudo_disable_scoped_defaults ENABLE
            apply_globals
            sha256sum /etc/sudoers.d/99-fic.conf > "$work/global-original"
        fi
        if [ ! -e "$work/unproven-wrappers" ]; then
            sed -n '/^#@FIC_SUDO_DISABLED_BEGIN /,/^#@FIC_SUDO_DISABLED_END /p' "$source" | \
                sed 's/policy=sudo_disable_scoped_defaults /policy=unregistered_policy /g' > "$work/unproven-wrappers"
        fi
        "$driver" apply sudo_disable_scoped_defaults ENABLE
        sha256sum -c "$work/global-original"
        visudo -c
        test "$(grep -c '^#@FIC_SUDO_DISABLED_BEGIN' "$source")" = 4
        if grep '^Defaults[:@>!]' "$source"; then
            echo 'FAIL active contextual Defaults survived scoped apply'
            exit 1
        fi
        runuser -u fic-scoped-native -- env FIC_SCOPED_SECRET=must_disappear sudo -n /usr/bin/env > "$work/environment"
        grep '^PATH=/usr/sbin:/usr/bin:/sbin:/bin$' "$work/environment"
        if grep '^FIC_SCOPED_SECRET=' "$work/environment"; then exit 1; fi
        prove_permissions
        if [ "$release_order" = global-first ]; then
            release_globals
            test ! -e /etc/sudoers.d/99-fic.conf
            "$driver" apply sudo_disable_scoped_defaults ENABLE
            "$driver" release sudo_disable_scoped_defaults
        else
            "$driver" release sudo_disable_scoped_defaults
            sha256sum -c "$work/global-original"
            release_globals
        fi
        "$driver" release sudo_disable_scoped_defaults
        visudo -c
        sha256sum -c "$work/source-original"
        sha256sum -c "$work/main-original"
        prove_permissions
        echo "PASS native shared scoped/global $apply_order apply and $release_order release"
    done
done

apply_globals
cat /etc/sudoers.d/99-fic.conf > "$work/owned-original"
printf 'Defaults:fic-scoped-native !authenticate\n' >> /etc/sudoers.d/99-fic.conf
sha256sum /etc/sudoers.d/99-fic.conf > "$work/drift"
if "$driver" apply sudo_disable_scoped_defaults ENABLE; then
    echo 'FAIL scoped policy adopted foreign content injected into global container'
    exit 1
fi
sha256sum -c "$work/drift"
sha256sum -c "$work/source-original"
# Resolve only the artificial test drift; production never restores snapshots.
cat "$work/owned-original" > /etc/sudoers.d/99-fic.conf
release_globals
echo 'PASS native global container drift blocks scoped mutation without overwriting foreign bytes'

source_size=$(wc -c < "$source")
printf '\n' >> "$source"
cat "$work/unproven-wrappers" >> "$source"
visudo -c
sha256sum "$source" > "$work/unproven-state"
if "$driver" apply sudo_disable_scoped_defaults ENABLE; then
    echo 'FAIL scoped policy ignored unproven other wrapper owner'
    exit 1
fi
sha256sum -c "$work/unproven-state"
# The test administrator removes only the appended synthetic marker bytes.
head -c "$source_size" "$source" > "$work/without-test-markers"
cat "$work/without-test-markers" > "$source"
sha256sum -c "$work/source-original"
echo 'PASS native unproven other wrapper policy blocks scoped mutation'

# A global-first include adds a separator to an unterminated foreign main.
# Scoped wrappers change that prefix, so global release must refuse until
# scoped release restores the proven prefix. The failed global owner still
# has its exact target and must not deadlock that safe scoped release.
printf '\nDefaults:fic-scoped-native passwd_tries=5' >> /etc/sudoers
sha256sum /etc/sudoers > "$work/unterminated-original"
if [ "$rust_provider" = yes ]; then
    if "$driver" apply sudo_passwd_tries 3 || "$driver" apply sudo_disable_scoped_defaults ENABLE; then
        echo 'FAIL sudo-rs repaired an invalid unterminated main implicitly'
        exit 1
    fi
    sha256sum -c "$work/unterminated-original"
    sha256sum -c "$work/source-original"
    test ! -e /etc/sudoers.d/99-fic.conf
    echo 'PASS sudo-rs rejects unterminated main without global/scoped mutation'
    exit 0
fi
"$driver" apply sudo_passwd_tries 3
"$driver" apply sudo_disable_scoped_defaults ENABLE
if "$driver" release sudo_passwd_tries; then
    echo 'FAIL unproven unterminated prefix separator was released'
    exit 1
fi
grep '^Defaults passwd_tries=3$' /etc/sudoers.d/99-fic.conf
"$driver" release sudo_disable_scoped_defaults
"$driver" release sudo_passwd_tries
sha256sum -c "$work/unterminated-original"
sha256sum -c "$work/source-original"
visudo -c
echo 'PASS native unterminated prefix Conflict and safe scoped-first recovery'
