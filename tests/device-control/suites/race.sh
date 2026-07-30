#!/usr/bin/env bash

wait_for_background_jobs() {
    local failures=0
    local pid
    for pid in "$@"; do
        if ! wait "$pid"; then
            failures=$((failures + 1))
        fi
    done
    [[ "$failures" -eq 0 ]] || fail "$failures background jobs failed"
}

test_concurrent_ipc_status_and_tree_reads() {
    local response ok
    response=$(remote_sudo "python3 $(printf '%q' "$REMOTE_HELPER") stress-read 12 5") || return
    ok=$(printf '%s\n' "$response" | json_field ok)
    expect_eq "$ok" "True" "concurrent local IPC reads must succeed"
}

test_rapid_virtio_attach_detach_cycles_are_consistent() {
    detach_disk "$VIRTIO_TARGET"
    create_test_image "$VIRTIO_DISK" || return
    local i response connected_count
    for i in $(seq 1 3); do
        attach_disk "$VIRTIO_DISK" "$VIRTIO_TARGET" virtio "$VIRTIO_SERIAL" || return
        remote_sudo "udevadm settle --timeout=20" || return
        response=$(wait_for_attr DEVNAME "/dev/$VIRTIO_TARGET" true 30) || return
        expect_eq "$(printf '%s\n' "$response" | device_field connected)" "True" "virtio cycle $i must connect" || return
        detach_disk "$VIRTIO_TARGET"
        remote_sudo "udevadm settle --timeout=20" || return
        response=$(wait_for_attr DEVNAME "/dev/$VIRTIO_TARGET" false 30) || return
        expect_eq "$(printf '%s\n' "$response" | device_field connected)" "False" "virtio cycle $i must disconnect" || return
    done
    connected_count=$(count_device_any_attr DEVNAME "/dev/$VIRTIO_TARGET" true)
    [[ "$connected_count" -eq 0 ]] || fail "rapid virtio cycles left $connected_count connected history rows"
}

test_policy_toggle_during_usb_hotplug_keeps_daemon_responsive() {
    detach_disk "$USB_BLOCKED_TARGET"
    create_test_image "$USB_BLOCKED_DISK" || return
    local toggler response count
    (
        set_usb_storage_policy true >/dev/null
        sleep 1
        set_usb_storage_policy false >/dev/null
        sleep 1
        set_usb_storage_policy true >/dev/null
    ) &
    toggler=$!

    attach_disk "$USB_BLOCKED_DISK" "$USB_BLOCKED_TARGET" usb "$USB_BLOCKED_SERIAL" || {
        wait "$toggler" || true
        return 1
    }
    remote_sudo "udevadm settle --timeout=20" || true
    wait "$toggler" || return
    response=$(wait_for_test_disk "$USB_BLOCKED_SERIAL" "/dev/$USB_BLOCKED_TARGET" "" 60) || return
    count=$(count_device_any_attr "ID_SERIAL,ID_SERIAL_SHORT,SERIAL" "$USB_BLOCKED_SERIAL" true)
    [[ "$count" -le 1 ]] || fail "policy toggle hotplug left $count connected rows for one USB serial"
    device_ipc '{"command":"status"}' >/dev/null || return
    reset_device_from_response "$response"
    detach_disk "$USB_BLOCKED_TARGET"
}

run_race_suite() {
    run_test "concurrent IPC status and tree reads succeed" test_concurrent_ipc_status_and_tree_reads
    run_test "rapid virtio attach/detach cycles are consistent" test_rapid_virtio_attach_detach_cycles_are_consistent
    run_test "policy toggle during USB hotplug keeps daemon responsive" test_policy_toggle_during_usb_hotplug_keeps_daemon_responsive
}
