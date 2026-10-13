#!/bin/sh
set -eu
test -f /run/.containerenv
test "$(id -u)" = 0
driver=$1
work=$(mktemp -d /tmp/fic-global-native-XXXXXX)
trap 'rm -rf "$work"' EXIT HUP INT TERM
main_mode=$(stat -c '%a' /etc/sudoers)
# ALT's packaged sudoers deliberately grants no commands to root. Give the
# fixture a native query identity without changing the packaged main file.
query_fixture=/etc/sudoers.d/97-fic-native-query
test ! -e "$query_fixture"
printf 'root ALL=(ALL) ALL\n' > "$query_fixture"
chmod "$main_mode" "$query_fixture"
sha256sum /etc/sudoers > "$work/original.sha256"
visudo -c
"$driver" provider
"$driver" apply sudo_env_reset ENABLE
"$driver" apply sudo_passwd_tries 3
"$driver" apply sudo_securepath /usr/sbin:/usr/bin:/sbin:/bin
"$driver" apply sudo_timeout 10
"$driver" apply sudo_exempt_group_disable DISABLE
visudo -c
sudo -l -U root | sed 's/\\:/:/g' > "$work/defaults"
grep -F 'passwd_tries=3' "$work/defaults"
grep -F 'timestamp_timeout=10' "$work/defaults"
grep -F 'secure_path=/usr/sbin:/usr/bin:/sbin:/bin' "$work/defaults"
echo 'PASS five global policies and native effective Defaults'

for policy in sudo_env_reset sudo_passwd_tries sudo_securepath sudo_timeout sudo_exempt_group_disable; do
    case "$policy" in
        sudo_env_reset) value=ENABLE ;;
        sudo_passwd_tries) value=3 ;;
        sudo_securepath) value=/usr/sbin:/usr/bin:/sbin:/bin ;;
        sudo_timeout) value=10 ;;
        sudo_exempt_group_disable) value=DISABLE ;;
    esac
    "$driver" apply "$policy" "$value"
done
echo 'PASS reapply preserves global ownership'

# Read the same .conf first with only the native includedir, then with the
# final explicit include. A real sudo query, not FIC's parser, proves both.
test ! -e /etc/sudoers.d/98-fic-native-probe
printf 'Defaults passwd_tries=4\n' > /etc/sudoers.d/98-fic-native-probe
chmod "$main_mode" /etc/sudoers.d/98-fic-native-probe
sed '/^#@FIC_INCLUDE_BEGIN$/,$d' /etc/sudoers > "$work/prefix"
cat "$work/prefix" > /etc/sudoers
sudo -l -U root | sed 's/\\:/:/g' > "$work/ignored"
grep -F 'passwd_tries=4' "$work/ignored"
echo 'PASS .conf is ignored by native includedir'
printf '#@FIC_INCLUDE_BEGIN\n@include /etc/sudoers.d/99-fic.conf\n#@FIC_INCLUDE_END\n' >> /etc/sudoers
sudo -l -U root | sed 's/\\:/:/g' > "$work/explicit"
grep -F 'passwd_tries=3' "$work/explicit"
echo 'PASS explicit include reads .conf at EOF'
rm /etc/sudoers.d/98-fic-native-probe

# Foreign contextual Defaults remain active and do not invalidate global
# success. Scoped suppression is checked separately by its own native gate.
useradd -m fic-global-context
printf 'Defaults:fic-global-context timestamp_timeout=99\nfic-global-context ALL=(root) /usr/bin/true\n' > /etc/sudoers.d/98-fic-native-context
chmod "$main_mode" /etc/sudoers.d/98-fic-native-context
"$driver" apply sudo_timeout 10
sudo -l -U fic-global-context > "$work/context" 2>&1 || true
grep -F 'timestamp_timeout=99' "$work/context"
echo 'PASS contextual Defaults coexist with independent global success'

"$driver" apply sudo_passwd_tries 4
sudo -l -U root | sed 's/\\:/:/g' > "$work/refreshed"
grep -F 'passwd_tries=4' "$work/refreshed"
"$driver" apply sudo_passwd_tries 3
echo 'PASS value refresh through production policy and journal'

# A drifted placement must not be repaired implicitly.
printf '# foreign after FIC block\n' >> /etc/sudoers
sha256sum /etc/sudoers > "$work/drift.sha256"
if "$driver" apply sudo_timeout 10; then
    echo 'FAIL foreign content after FIC block was accepted'
    exit 1
fi
sha256sum -c "$work/drift.sha256"
sed '$d' /etc/sudoers > "$work/repaired-fixture"
cat "$work/repaired-fixture" > /etc/sudoers
echo 'PASS EOF placement drift is refused without overwriting foreign bytes'

for policy in sudo_securepath sudo_env_reset sudo_exempt_group_disable sudo_timeout sudo_passwd_tries; do
    "$driver" release "$policy"
    visudo -c
done
test ! -e /etc/sudoers.d/99-fic.conf
sha256sum -c "$work/original.sha256"
grep -F 'timestamp_timeout=99' /etc/sudoers.d/98-fic-native-context
rm /etc/sudoers.d/98-fic-native-context
rm "$query_fixture"
echo 'PASS independent rollback and last owner preserve foreign native configuration'
