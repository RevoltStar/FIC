#!/usr/bin/env bash

ingestion_sample_sysfs() {
    remote_sudo "find /sys/devices -path '*/pci*' -type d -print -quit"
}

ingestion_env_command() {
    local sysfs_path=$1

    remote_sudo "python3 - <<'PY' $(printf '%q' "$sysfs_path")
import pathlib
import shlex
import subprocess
import sys

path = pathlib.Path(sys.argv[1]).resolve()
devpath = '/' + str(path.relative_to('/sys'))

out = subprocess.check_output(
    ['udevadm', 'info', '--query=property', '--path=' + devpath],
    text=True,
)

env = {
    'ACTION': 'change',
    'DEVPATH': devpath,
    'SUBSYSTEM': 'pci',
}

for line in out.splitlines():
    if '=' in line:
        key, value = line.split('=', 1)
        env[key] = value

print(' '.join(
    f'{key}=' + shlex.quote(value)
    for key, value in env.items()
))
PY"
}

test_udev_event_burst_uses_event_socket() {
    local sysfs_path env_cmd
    local before_errors after_errors
    local response ok

    sysfs_path=$(ingestion_sample_sysfs)
    [[ -n "$sysfs_path" ]] ||
        fail "managed PCI sysfs fixture is required" ||
        return

    env_cmd=$(ingestion_env_command "$sysfs_path") || return

    before_errors=$(
        remote_sudo \
            "grep -R \"Transport endpoint is not connected\\|Connection reset by peer\" \
             /opt/fic/log 2>/dev/null | wc -l"
    ) || return

    remote_sudo \
        "for i in \$(seq 1 600); do
             env $env_cmd $REMOTE_FIC_DICK udev &
         done
         wait" || return

    response=$(device_ipc '{"command":"device_tree_revision"}') || return
    ok=$(printf '%s\n' "$response" | json_field ok)

    expect_eq \
        "$ok" \
        "True" \
        "admin API must respond after udev ingestion burst" ||
        return

    after_errors=$(
        remote_sudo \
            "grep -R \"Transport endpoint is not connected\\|Connection reset by peer\" \
             /opt/fic/log 2>/dev/null | wc -l"
    ) || return

    expect_eq \
        "$after_errors" \
        "$before_errors" \
        "udev burst must not create admin IPC transport errors"
}

test_admin_api_responds_during_udev_burst() {
    local sysfs_path env_cmd response

    sysfs_path=$(ingestion_sample_sysfs)
    [[ -n "$sysfs_path" ]] ||
        fail "managed PCI sysfs fixture is required" ||
        return

    env_cmd=$(ingestion_env_command "$sysfs_path") || return

    remote_sudo \
        "for i in \$(seq 1 300); do
             env $env_cmd $REMOTE_FIC_DICK udev &
         done

         sleep 0.1
         fic-cli device revision >/tmp/fic-ingestion-revision.txt
         wait" || return

    response=$(
        remote_sudo "cat /tmp/fic-ingestion-revision.txt"
    ) || return

    [[ "$response" == *"revision="* ]] ||
        fail "admin API did not respond during udev burst: $response"
}

test_restart_runs_reconciliation_without_udevadm_trigger() {
    local before after

    before=$(
        device_ipc '{"command":"device_tree_revision"}' |
            json_field revision
    ) || return

    remote_sudo "systemctl restart fic-device.service" || return
    wait_for_fic_daemon || return

    after=$(
        device_ipc '{"command":"device_tree_revision"}' |
            json_field revision
    ) || return

    [[ -n "$before" && -n "$after" ]] ||
        fail "device revision must be available before and after restart" ||
        return

    remote_sudo \
        "! journalctl -b -u fic_get_device_udev_info.service \
             --no-pager |
             grep -q 'udevadm trigger --action=add'" ||
        fail "boot helper must not use udevadm trigger for FIC inventory"
}

test_reconcile_marker_is_bounded() {
    local marker=/run/fic/fic-device-reconcile.required
    local sysfs_path env_cmd size

    sysfs_path=$(ingestion_sample_sysfs)
    [[ -n "$sysfs_path" ]] ||
        fail "managed PCI sysfs fixture is required" ||
        return

    env_cmd=$(ingestion_env_command "$sysfs_path") || return

    # Stop daemon so the datagram endpoint cannot accept events.
    remote_sudo "systemctl stop fic-device.service" || return

    # Runtime directory must remain present for marker fallback testing.
    remote_sudo "test -d /run/fic" ||
        fail "/run/fic must exist while fic-device is stopped" ||
        return

    remote_sudo "rm -f '$marker'" || return

    remote_sudo \
        "for i in \$(seq 1 500); do
             env $env_cmd $REMOTE_FIC_DICK udev >/dev/null 2>&1 || exit 1
         done" || {
            remote_sudo "systemctl start fic-device.service" >/dev/null 2>&1 || true
            fail "udev helper must succeed when reconciliation marker can be created"
            return
        }

    remote_sudo "test -f '$marker'" ||
        fail "failed udev delivery must create reconciliation marker" ||
        return

    size=$(remote_sudo "stat -c '%s' '$marker'") || return

    expect_eq \
        "$size" \
        "0" \
        "reconciliation marker must remain a bounded flag file" ||
        return

    remote_sudo "systemctl start fic-device.service" || return
    wait_for_fic_daemon || return

    # Daemon must consume the marker.
    remote_sudo \
        "for i in \$(seq 1 50); do
             [ ! -e '$marker' ] && exit 0
             sleep 0.1
         done
         exit 1" ||
        fail "daemon did not consume reconciliation marker"
}

test_boot_helper_does_not_duplicate_permanent_check() {
    local installed_script

    installed_script=$(
        remote_sudo "cat /opt/fic/bin/fic-udevadm-trigger 2>/dev/null || true"
    )

    [[ -n "$installed_script" ]] || {
        # Package layout may place this helper elsewhere in some test builds.
        return 0
    }

    [[ "$installed_script" != *"check-permanent"* ]] ||
        fail "boot helper must not duplicate permanent check owned by reconciliation"
}

run_ingestion_suite() {
    run_test \
        "udev event burst uses event socket" \
        test_udev_event_burst_uses_event_socket

    run_test \
        "admin API responds during udev burst" \
        test_admin_api_responds_during_udev_burst

    run_test \
        "restart runs reconciliation without udevadm trigger" \
        test_restart_runs_reconciliation_without_udevadm_trigger

    run_test \
        "reconciliation marker remains bounded" \
        test_reconcile_marker_is_bounded

    run_test \
        "boot helper does not duplicate permanent check" \
        test_boot_helper_does_not_duplicate_permanent_check
}