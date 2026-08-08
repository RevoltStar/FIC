#!/usr/bin/env bash

ingestion_sample_sysfs() {
    remote_sudo "find /sys/devices -path '*/pci*' -type d -print -quit"
}

ingestion_env_command() {
    local sysfs_path=$1
    remote_sudo "python3 - <<'PY' $(printf '%q' "$sysfs_path")
import pathlib, subprocess, sys
path = pathlib.Path(sys.argv[1]).resolve()
devpath = '/' + str(path.relative_to('/sys'))
out = subprocess.check_output(['udevadm', 'info', '--query=property', '--path=' + devpath], text=True)
env = {'ACTION': 'change', 'DEVPATH': devpath, 'SUBSYSTEM': 'pci'}
for line in out.splitlines():
    if '=' in line:
        k, v = line.split('=', 1)
        env[k] = v
print(' '.join(f'{k}=' + __import__('shlex').quote(v) for k, v in env.items()))
PY"
}

test_udev_event_burst_uses_event_socket() {
    local sysfs_path env_cmd before_errors after_errors response ok
    sysfs_path=$(ingestion_sample_sysfs)
    [[ -n "$sysfs_path" ]] || fail "managed PCI sysfs fixture is required" || return
    env_cmd=$(ingestion_env_command "$sysfs_path") || return

    before_errors=$(remote_sudo "grep -R \"Transport endpoint is not connected\\|Connection reset by peer\" /opt/fic/log 2>/dev/null | wc -l") || return
    remote_sudo "for i in \$(seq 1 600); do env $env_cmd $REMOTE_FIC_DICK udev & done; wait" || return
    response=$(device_ipc '{"command":"device_tree_revision"}') || return
    ok=$(printf '%s\n' "$response" | json_field ok)
    expect_eq "$ok" "True" "admin API must respond after udev ingestion burst" || return
    after_errors=$(remote_sudo "grep -R \"Transport endpoint is not connected\\|Connection reset by peer\" /opt/fic/log 2>/dev/null | wc -l") || return
    expect_eq "$after_errors" "$before_errors" "udev burst must not create admin IPC transport errors" || return
}

test_admin_api_responds_during_udev_burst() {
    local sysfs_path env_cmd response ok
    sysfs_path=$(ingestion_sample_sysfs)
    [[ -n "$sysfs_path" ]] || fail "managed PCI sysfs fixture is required" || return
    env_cmd=$(ingestion_env_command "$sysfs_path") || return

    remote_sudo "for i in \$(seq 1 300); do env $env_cmd $REMOTE_FIC_DICK udev & done; sleep 0.1; fic-cli device revision >/tmp/fic-ingestion-revision.txt; wait" || return
    response=$(remote_sudo "cat /tmp/fic-ingestion-revision.txt") || return
    [[ "$response" == *"revision="* ]] || fail "admin API did not respond during udev burst: $response"
}

test_restart_runs_reconciliation_without_udevadm_trigger() {
    local before after
    before=$(device_ipc '{"command":"device_tree_revision"}' | json_field revision) || return
    remote_sudo "systemctl restart fic-device.service" || return
    wait_for_fic_daemon || return
    after=$(device_ipc '{"command":"device_tree_revision"}' | json_field revision) || return
    [[ -n "$before" && -n "$after" ]] || fail "device revision must be available before and after restart" || return
    remote_sudo "! journalctl -b -u fic_get_device_udev_info.service --no-pager | grep -q 'udevadm trigger --action=add'" ||
        fail "boot helper must not use udevadm trigger for FIC inventory"
}

run_ingestion_suite() {
    run_test "udev event burst uses event socket" test_udev_event_burst_uses_event_socket
    run_test "admin API responds during udev burst" test_admin_api_responds_during_udev_burst
    run_test "restart runs reconciliation without udevadm trigger" test_restart_runs_reconciliation_without_udevadm_trigger
}
