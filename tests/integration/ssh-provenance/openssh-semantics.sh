#!/bin/sh
# Run only inside a disposable container, never against the host service.
set -eu
[ "${FIC_DISPOSABLE_NATIVE:-}" = 1 ] || { echo 'Disposable container required' >&2; exit 2; }
sshd=$(command -v sshd || printf /usr/sbin/sshd)
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT
mkdir -p /run/sshd
ssh-keygen -q -t ed25519 -N '' -f "$fixture/hostkey"
cat > "$fixture/base" <<EOF
HostKey $fixture/hostkey
Port 2222
PermitRootLogin no
PubkeyAuthentication yes
MaxAuthTries 3
UsePAM yes
EOF
cat "$fixture/base" > "$fixture/match"
cat >> "$fixture/match" <<'EOF'
Match User root
 PermitRootLogin yes
 PubkeyAuthentication no
 MaxAuthTries 6
EOF
"$sshd" -T -f "$fixture/match" > "$fixture/global"
"$sshd" -T -f "$fixture/match" -C user=root,host=localhost,addr=127.0.0.1 > "$fixture/conditional"
grep -qx 'permitrootlogin no' "$fixture/global"
grep -qx 'pubkeyauthentication yes' "$fixture/global"
grep -qx 'maxauthtries 3' "$fixture/global"
grep -qx 'permitrootlogin yes' "$fixture/conditional"
grep -qx 'pubkeyauthentication no' "$fixture/conditional"
grep -qx 'maxauthtries 6' "$fixture/conditional"
echo 'OPENSSH PASS: real Match User root overrides root/pubkey/maxtries despite compliant global -T'
cat "$fixture/base" > "$fixture/pam"
printf '\nMatch User root\n UsePAM no\n' >> "$fixture/pam"
if "$sshd" -T -f "$fixture/pam" > /dev/null 2> "$fixture/error"; then
 echo 'FAIL: UsePAM unexpectedly allowed in Match' >&2; exit 1
fi
grep -q 'not allowed within a Match block' "$fixture/error"
echo 'OPENSSH PASS: UsePAM is global-only; invalid Match is not a weakening fixture'
printf 'Port 2200\n' > "$fixture/extra"
cat "$fixture/base" > "$fixture/ports"
printf '\nInclude %s/extra\n' "$fixture" >> "$fixture/ports"
"$sshd" -T -f "$fixture/ports" > "$fixture/output"
grep -qx 'port 2222' "$fixture/output"
grep -qx 'port 2200' "$fixture/output"
[ "$(grep -c '^port ' "$fixture/output")" = 2 ]
echo 'OPENSSH PASS: included additional port survives owned first Port'
"$sshd" -V 2>&1
