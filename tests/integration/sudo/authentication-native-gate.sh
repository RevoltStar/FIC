#!/bin/sh
set -eu
driver=$1
work=/var/lib/fic-auth-native-gate
mkdir -p "$work"
mode=0440
if command -v control >/dev/null 2>&1; then mode=0400; fi
source=/etc/sudoers.d/98-fic-auth-native
useradd -m fic-auth-native
printf 'fic-auth-native:FicNative1!\n' | chpasswd
if command -v control >/dev/null 2>&1; then control sudo wheelonly; usermod -a -G wheel fic-auth-native; fi
provider=$("$driver" provider)
tag=''
rust=no
case "$provider" in *provider=classic*) tag='NOEXEC: ';; *provider=sudo-rs*) rust=yes;; esac
printf 'Defaults:fic-auth-native !authenticate\r\nfic-auth-native ALL=(root) %sNOPASSWD: /usr/bin/printf allowed argument, \\\n    /usr/bin/true, PASSWD: /usr/bin/id\n' "$tag" > "$source"
chmod "$mode" "$source"
if [ "$rust" = yes ]; then
    sha256sum "$source" > "$work/unsupported-authenticate"
    if visudo -c || "$driver" apply sudo_require_authentication ENABLE; then echo 'FAIL sudo-rs admitted unsupported authenticate flag'; exit 1; fi
    sha256sum -c "$work/unsupported-authenticate"
    test ! -e /etc/sudoers.d/99-fic.conf
    sed 's/!authenticate/timestamp_timeout=0/' "$source" > "$work/supported"
    cat "$work/supported" > "$source"
    echo 'PASS sudo-rs unsupported authenticate rejected before mutation'
    sha256sum "$source" > "$work/unsupported-crlf"
    if visudo -c || "$driver" apply sudo_require_authentication ENABLE; then echo 'FAIL sudo-rs admitted unsupported CRLF directive'; exit 1; fi
    sha256sum -c "$work/unsupported-crlf"
    printf 'Defaults:fic-auth-native timestamp_timeout=0\nfic-auth-native ALL=(root) NOPASSWD: /usr/bin/printf allowed argument, \\\n    /usr/bin/true, PASSWD: /usr/bin/id\n' > "$source"
    echo 'PASS sudo-rs unsupported CRLF refused without normalization'
fi
cp "$source" "$work/original"
sha256sum /etc/sudoers > "$work/main-original"
visudo -c
"$driver" intent sudo_disable_scoped_defaults DISABLE
"$driver" intent sudo_require_authentication DISABLE
"$driver" apply sudo_exempt_group_disable DISABLE
"$driver" apply sudo_timeout 0
allowed_password() {
    printf 'FicNative1!\n' | runuser -u fic-auth-native -- sudo -k -S /usr/bin/printf allowed argument > "$work/allowed"
    grep -qx allowed "$work/allowed"
}
forbidden_password() {
    if printf 'FicNative1!\n' | runuser -u fic-auth-native -- sudo -k -S /usr/bin/printf forbidden > "$work/denied" 2>&1; then
        echo 'FAIL broadened argument permissions'; exit 1
    fi
}
runuser -u fic-auth-native -- sudo -k -n /usr/bin/printf allowed argument > "$work/before"
grep -qx allowed "$work/before"
forbidden_password
"$driver" apply sudo_require_authentication ENABLE
visudo -c
if runuser -u fic-auth-native -- sudo -k -n /usr/bin/printf allowed argument; then echo 'FAIL authentication bypass survived'; exit 1; fi
allowed_password
forbidden_password
"$driver" apply sudo_require_authentication ENABLE
echo 'PASS reversible authentication, inherited tags and command argument permissions'
# Drift must preserve the manually edited bytes.
cp "$source" "$work/applied"
sed 's/PASSWD: \/usr\/bin\/printf/PASSWD: \/usr\/bin\/true/' "$work/applied" > "$source"
sha256sum "$source" > "$work/drift"
if "$driver" release sudo_require_authentication; then echo 'FAIL accepted drifted replacement'; exit 1; fi
sha256sum -c "$work/drift"
cp "$work/applied" "$source"
"$driver" release sudo_require_authentication
cmp "$source" "$work/original"
echo 'PASS drift refusal and byte-exact release retry'
if [ "$rust" = no ]; then
# auth first: scope cannot wrap its active contextual replacement, and
# requested scope without a record protects auth release.
"$driver" apply sudo_require_authentication ENABLE
if "$driver" apply sudo_disable_scoped_defaults ENABLE; then echo 'FAIL nested ownership'; exit 1; fi
sha256sum "$source" > "$work/overlap"
if "$driver" release sudo_require_authentication; then echo 'FAIL ignored requested scope without journal'; exit 1; fi
sha256sum -c "$work/overlap"
"$driver" release sudo_disable_scoped_defaults
"$driver" release sudo_require_authentication
cmp "$source" "$work/original"
echo 'PASS auth-first requested-state conflicts and safe release order'
# scope first: its inactive original is skipped by auth, yet remains guarded
# when auth is requested. Only auth owns the active command rule.
"$driver" apply sudo_disable_scoped_defaults ENABLE
"$driver" apply sudo_require_authentication ENABLE
allowed_password
forbidden_password
if "$driver" release sudo_disable_scoped_defaults; then echo 'FAIL restored !authenticate while auth requested'; exit 1; fi
"$driver" release sudo_require_authentication
"$driver" release sudo_disable_scoped_defaults
cmp "$source" "$work/original"
echo 'PASS scoped-first authentication and protected rollback'
else
    for order in auth-first scoped-first; do
        for release_order in auth-first scoped-first; do
            if [ "$order" = auth-first ]; then
                "$driver" apply sudo_require_authentication ENABLE
                "$driver" apply sudo_disable_scoped_defaults ENABLE
            else
                "$driver" apply sudo_disable_scoped_defaults ENABLE
                "$driver" apply sudo_require_authentication ENABLE
            fi
            allowed_password
            forbidden_password
            if [ "$release_order" = auth-first ]; then
                "$driver" release sudo_require_authentication
                "$driver" release sudo_disable_scoped_defaults
            else
                "$driver" release sudo_disable_scoped_defaults
                allowed_password
                "$driver" release sudo_require_authentication
            fi
            cmp "$source" "$work/original"
            echo "PASS sudo-rs supported contextual defaults $order $release_order"
        done
    done
fi
# Process cuts after journal, first file and postcondition; no destructor runs.
second=/etc/sudoers.d/98-fic-auth-native-second
printf 'fic-auth-native ALL=(root) NOPASSWD: /usr/bin/true\n' > "$second"
chmod "$mode" "$second"
cp "$second" "$work/second-original"
for phase in before_prepared prepared file postcondition; do
    "$driver" intent sudo_disable_scoped_defaults DISABLE
    "$driver" intent sudo_require_authentication ENABLE
    set +e
    "$driver" crash-apply sudo_require_authentication ENABLE "$phase"
    code=$?
    set -e
    test "$code" = 86
    "$driver" apply sudo_require_authentication ENABLE
    allowed_password
    forbidden_password
    "$driver" release sudo_require_authentication
    cmp "$source" "$work/original"
    cmp "$second" "$work/second-original"
    echo "PASS native process crash auth $phase"
done
# Crash during partial release leaves live journal authority for the subset.
"$driver" apply sudo_require_authentication ENABLE
set +e
"$driver" crash-release sudo_require_authentication release_file
code=$?
set -e
test "$code" = 86
"$driver" release sudo_require_authentication
cmp "$source" "$work/original"
cmp "$second" "$work/second-original"
rm "$second"
echo 'PASS native partial release crash recovery'
# A nested explicit include contains aliases and its own auth mutation.
nested=/etc/sudoers.d/fic-auth-native.nested
mkdir "$nested"
leaf=$nested/leaf.conf
printf 'User_Alias FIC_AUTH_USERS = fic-auth-native\nCmnd_Alias FIC_AUTH_ARGS = /usr/bin/printf allowed argument, /usr/bin/true\nFIC_AUTH_USERS ALL=(root) NOPASSWD: FIC_AUTH_ARGS\n' > "$leaf"
chmod "$mode" "$leaf"
printf '@include %s\n' "$leaf" >> "$source"
cp "$source" "$work/nested-source"
cp "$leaf" "$work/nested-original"
visudo -c
"$driver" apply sudo_require_authentication ENABLE
allowed_password
forbidden_password
printf '# foreign concurrent comment\n' >> "$leaf"
"$driver" release sudo_require_authentication
cmp "$source" "$work/nested-source"
cat "$work/nested-original" > "$work/nested-expected"
printf '# foreign concurrent comment\n' >> "$work/nested-expected"
cmp "$leaf" "$work/nested-expected"
echo 'PASS nested includes, aliases, Runas and foreign comment preserved'
if [ "$rust" = no ]; then
    # Classic native syntax accepts an unterminated final command rule.
    sed '$s/$//' "$work/nested-original" | head -c -1 > "$leaf"
    cp "$leaf" "$work/no-lf-original"
    visudo -c
    "$driver" apply sudo_require_authentication ENABLE
    allowed_password
    forbidden_password
    "$driver" release sudo_require_authentication
    cmp "$leaf" "$work/no-lf-original"
    echo 'PASS native byte-exact no-final-LF authentication rollback'
fi
cp "$work/original" "$source"
rm "$leaf"
rmdir "$nested"
if [ "$rust" = no ]; then
# Scope owns the only bypass; authentication is a proven no-op with no record.
printf 'Defaults:fic-auth-native !authenticate\nfic-auth-native ALL=(root) PASSWD: /usr/bin/printf allowed argument\n' > "$source"
cp "$source" "$work/noop-original"
"$driver" apply sudo_disable_scoped_defaults ENABLE
"$driver" apply sudo_require_authentication ENABLE > "$work/noop-result"
grep -q 'active-policy-records=0' "$work/noop-result"
if "$driver" release sudo_disable_scoped_defaults; then echo 'FAIL ignored no-record authentication intent'; exit 1; fi
"$driver" release sudo_require_authentication
"$driver" release sudo_disable_scoped_defaults
cmp "$source" "$work/noop-original"
cp "$work/original" "$source"
echo 'PASS requested authentication without mutation record guards scope release'
fi
# Native syntax refusal precedes all mutation, including a valid earlier file.
printf 'fic-auth-native ALL=(root) NOPASSWD: /usr/bin/true,\n' > "$second"
chmod "$mode" "$second"
sha256sum "$source" "$second" > "$work/invalid"
if "$driver" apply sudo_require_authentication ENABLE; then echo 'FAIL partial apply on native-invalid graph'; exit 1; fi
sha256sum -c "$work/invalid"
rm "$second"
"$driver" release sudo_require_authentication
echo 'PASS native-invalid graph refused before mutation'

cp /etc/sudoers "$work/main-with-globals"
# Unknown family markers must be refused before any sudoers mutation.
printf '#@FIC_AUTH_UNKNOWN\n' >> "$source"
sha256sum "$source" > "$work/unknown"
if "$driver" apply sudo_require_authentication ENABLE; then echo 'FAIL unknown auth marker'; exit 1; fi
sha256sum -c "$work/unknown"
cp "$work/original" "$source"
"$driver" release sudo_require_authentication
"$driver" release sudo_timeout
"$driver" release sudo_exempt_group_disable
sha256sum -c "$work/main-original"
test ! -e /etc/sudoers.d/99-fic.conf
visudo -c
echo 'PASS unknown-marker refusal and independent global ownership release'
