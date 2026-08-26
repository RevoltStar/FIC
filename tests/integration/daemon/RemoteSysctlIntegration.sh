#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 /path/to/sysctl_configuration_tests" >&2
    exit 2
fi

driver=$1
main=/etc/sysctl.conf
managed=/etc/sysctl.d/zzzz-fic.conf
etc_dir=/etc/sysctl.d
run_dir=/run/sysctl.d
backup=$(mktemp -d /root/fic-sysctl-integration.XXXXXX)
run_dir_existed=0
main_existed=0
managed_existed=0

if [[ -d "$run_dir" ]]; then
    run_dir_existed=1
else
    install -d -o root -g root -m 0755 "$run_dir"
fi
if [[ -e "$main" || -L "$main" ]]; then
    main_existed=1
    cp -a "$main" "$backup/sysctl.conf"
fi
if [[ -e "$managed" || -L "$managed" ]]; then
    managed_existed=1
    cp -a "$managed" "$backup/zzzz-fic.conf"
fi

test_files=(
    "$managed"
    "$etc_dir/41-fic-remote-order.conf"
    "$run_dir/91-fic-remote-order.conf"
    "$etc_dir/55-fic-remote-same.conf"
    "$run_dir/55-fic-remote-same.conf"
    "$etc_dir/56-fic-remote-mask.conf"
    "$run_dir/56-fic-remote-mask.conf"
    "$etc_dir/57-fic-remote-symlink.conf"
    "$etc_dir/98-fic-remote-unsafe.conf"
)

cleanup() {
    rm -f "${test_files[@]}"
    if [[ $main_existed -eq 1 ]]; then
        cp -a "$backup/sysctl.conf" "$main"
    else
        rm -f "$main"
    fi
    if [[ $managed_existed -eq 1 ]]; then
        cp -a "$backup/zzzz-fic.conf" "$managed"
    else
        rm -f "$managed"
    fi
    if [[ $run_dir_existed -eq 0 ]]; then
        rmdir "$run_dir" 2>/dev/null || true
    fi
    rm -rf "$backup"
}
trap cleanup EXIT

assert_value() {
    local key=$1
    local expected=$2
    local actual
    actual=$($driver --inspect "$key" | cut -f1)
    if [[ "$actual" != "$expected" ]]; then
        echo "unexpected value for $key: expected '$expected', got '$actual'" >&2
        exit 1
    fi
}

printf '%s\n' 'net.ipv4.conf.default.send_redirects = 0' > \
    "$etc_dir/41-fic-remote-order.conf"
printf '%s\n' 'net.ipv4.conf.default.send_redirects = 1' > \
    "$run_dir/91-fic-remote-order.conf"
chmod 0644 "$etc_dir/41-fic-remote-order.conf" "$run_dir/91-fic-remote-order.conf"
assert_value net.ipv4.conf.default.send_redirects 1
echo 'PASS: global lexical order across real directories'

printf '%s\n' 'net.ipv4.conf.default.accept_redirects = 0' > \
    "$etc_dir/55-fic-remote-same.conf"
printf '%s\n' 'net.ipv4.conf.default.accept_redirects = 1' > \
    "$run_dir/55-fic-remote-same.conf"
chmod 0644 "$etc_dir/55-fic-remote-same.conf" "$run_dir/55-fic-remote-same.conf"
assert_value net.ipv4.conf.default.accept_redirects 0
echo 'PASS: same basename uses /etc over /run'

printf '%s\n' 'kernel.hostname = must-not-be-visible' > \
    "$run_dir/56-fic-remote-mask.conf"
ln -s /dev/null "$etc_dir/56-fic-remote-mask.conf"
assert_value kernel.hostname NOT_SET
echo 'PASS: /dev/null mask suppresses lower-priority file'

printf '%s\n' 'kernel.fic_remote_symlink = 1' > "$backup/fic-remote-symlink-target.conf"
chmod 0644 "$backup/fic-remote-symlink-target.conf"
ln -s "$backup/fic-remote-symlink-target.conf" "$etc_dir/57-fic-remote-symlink.conf"
assert_value kernel.fic_remote_symlink 1
echo 'PASS: regular foreign sysctl.d symlink is parsed'

baseline=$($driver --inspect kernel.pid_max | cut -f1)
main_before=$(sha256sum "$main" | cut -d' ' -f1)
$driver --ensure kernel.pid_max "$baseline" | grep -F $'OK\tUNCHANGED'
main_after=$(sha256sum "$main" | cut -d' ' -f1)
[[ "$main_before" == "$main_after" ]]
[[ ! -e "$managed" ]]
echo 'PASS: correct effective value does not create managed file or rewrite main file'

target=131072
if [[ "$baseline" == "$target" ]]; then
    target=262144
fi
$driver --ensure kernel.pid_max "$target" | grep -F $'OK\tCHANGED'
assert_value kernel.pid_max "$target"
[[ $(stat -c '%u:%g:%a' "$managed") == '0:0:644' ]]
grep -F "kernel.pid_max = $target" "$managed"
managed_checksum=$(sha256sum "$managed" | cut -d' ' -f1)
[[ $(sha256sum "$main" | cut -d' ' -f1) == "$main_before" ]]
$driver --ensure kernel.pid_max "$target" | grep -F $'OK\tUNCHANGED'
[[ $(sha256sum "$managed" | cut -d' ' -f1) == "$managed_checksum" ]]
echo 'PASS: managed override, metadata, untouched main file and idempotence'

$driver --ensure kernel.threads-max 8192 | grep -F $'OK\tCHANGED'
assert_value kernel.pid_max "$target"
assert_value kernel.threads-max 8192
echo 'PASS: values from multiple policies coexist in managed block'

printf '%s\n' 'kernel.pid_max = 1' 'this is not valid' > "$managed"
malformed_checksum=$(sha256sum "$managed" | cut -d' ' -f1)
if $driver --ensure kernel.pid_max "$target"; then
    echo 'malformed managed file unexpectedly accepted' >&2
    exit 1
fi
[[ $(sha256sum "$managed" | cut -d' ' -f1) == "$malformed_checksum" ]]
echo 'PASS: malformed managed file fails without write'

rm -f "$managed"
printf '%s\n' 'kernel.printk = 1 1 1 1' > "$etc_dir/98-fic-remote-unsafe.conf"
chmod 0666 "$etc_dir/98-fic-remote-unsafe.conf"
main_checksum=$(sha256sum "$main" | cut -d' ' -f1)
if $driver --ensure kernel.pid_max "$target"; then
    echo 'unsafe active file unexpectedly accepted' >&2
    exit 1
fi
[[ $(sha256sum "$main" | cut -d' ' -f1) == "$main_checksum" ]]
[[ ! -e "$managed" ]]
echo 'PASS: unsafe active file fails without write'

echo 'ALL REMOTE SYSCTL INTEGRATION TESTS PASSED'
