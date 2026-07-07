#!/usr/bin/env bash

test_device_ipc_status() {
    local response ok
    response=$(device_ipc '{"command":"status"}') || return
    ok=$(printf '%s\n' "$response" | json_field ok)
    expect_eq "$ok" "True" "device daemon status must be ok"
}

test_device_root() {
    local response ok device_id effective
    response=$(device_ipc '{"command":"device_root"}') || return
    ok=$(printf '%s\n' "$response" | json_field ok)
    device_id=$(printf '%s\n' "$response" | device_field id)
    effective=$(printf '%s\n' "$response" | device_field effective_control_level)
    expect_eq "$ok" "True" "device_root must be ok" || return
    expect_nonempty "$device_id" "device_root must return id" || return
    expect_eq "$effective" "allowed" "root effective policy must be allowed"
}

test_udev_trigger_pci_seen() {
    remote_sudo "udevadm trigger --subsystem-match=pci" || return
    remote_sudo "udevadm settle --timeout=20" || return
    remote_sudo "python3 $(printf '%q' "$REMOTE_HELPER") find-subsystem pci true" >/dev/null
}

test_attach_virtio_block_connected() {
    detach_disk "$VIRTIO_TARGET"
    create_test_image "$VIRTIO_DISK" || return
    attach_disk "$VIRTIO_DISK" "$VIRTIO_TARGET" virtio "$VIRTIO_SERIAL" || return
    remote_sudo "udevadm settle --timeout=20" || return
    local response connected subsystem
    response=$(wait_for_attr DEVNAME "/dev/$VIRTIO_TARGET" true 30) || return
    connected=$(printf '%s\n' "$response" | device_field connected)
    subsystem=$(printf '%s\n' "$response" | device_field subsystem)
    expect_eq "$connected" "True" "virtio block must be connected" || return
    expect_eq "$subsystem" "block" "virtio device must be recorded as block"
}

test_virtio_connect_event_recorded() {
    local response id events count
    response=$(find_device_attr DEVNAME "/dev/$VIRTIO_TARGET") || return
    id=$(printf '%s\n' "$response" | device_field id)
    events=$(remote_sudo "python3 $(printf '%q' "$REMOTE_HELPER") events $id 20") || return
    count=$(printf '%s\n' "$events" | python3 -c 'import json,sys; data=json.load(sys.stdin); print(sum(1 for e in data.get("events", []) if e.get("event_type") == "connect"))')
    [[ "$count" -ge 1 ]] || fail "virtio block must have at least one connect event"
}

test_detach_virtio_block_history() {
    detach_disk "$VIRTIO_TARGET"
    remote_sudo "udevadm settle --timeout=20" || return
    sleep 2
    local response connected
    response=$(wait_for_attr DEVNAME "/dev/$VIRTIO_TARGET" false 30) || return
    connected=$(printf '%s\n' "$response" | device_field connected)
    expect_eq "$connected" "False" "detached virtio block must remain in disconnected history"
}

test_detached_virtio_hidden_from_current_tree() {
    if find_current_device_attr DEVNAME "/dev/$VIRTIO_TARGET" >/dev/null 2>&1; then
        fail "detached virtio block must be hidden from current device tree"
        return
    fi
}

test_attach_usb_storage_allowed() {
    set_usb_storage_policy false false >/dev/null || return
    detach_disk "$USB_ALLOWED_TARGET"
    create_test_image "$USB_ALLOWED_DISK" || return
    attach_disk "$USB_ALLOWED_DISK" "$USB_ALLOWED_TARGET" usb "$USB_ALLOWED_SERIAL" || return
    remote_sudo "udevadm settle --timeout=20" || return
    local response effective id_bus
    response=$(wait_for_test_disk "$USB_ALLOWED_SERIAL" "/dev/$USB_ALLOWED_TARGET" true 45) || return
    reset_device_from_response "$response"
    response=$(find_device_any_attr "ID_SERIAL,ID_SERIAL_SHORT,SERIAL" "$USB_ALLOWED_SERIAL" true) || return
    effective=$(printf '%s\n' "$response" | device_field effective_control_level)
    id_bus=$(printf '%s\n' "$response" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("attributes", {}).get("ID_BUS", ""))')
    expect_eq "$effective" "allowed" "USB storage must be allowed while DC policy is disabled" || return
    expect_eq "$id_bus" "usb" "USB storage block device must have ID_BUS=usb"
}

test_attach_usb_storage_blocked_by_dc() {
    set_usb_storage_policy true true >/dev/null || return
    reset_test_device_controls
    detach_disk "$USB_BLOCKED_TARGET"
    create_test_image "$USB_BLOCKED_DISK" || return
    attach_disk "$USB_BLOCKED_DISK" "$USB_BLOCKED_TARGET" usb "$USB_BLOCKED_SERIAL" || return
    remote_sudo "udevadm settle --timeout=20" || true
    local response effective source
    response=$(wait_for_test_disk "$USB_BLOCKED_SERIAL" "/dev/$USB_BLOCKED_TARGET" "" 45) || return
    effective=$(printf '%s\n' "$response" | device_field effective_control_level)
    source=$(printf '%s\n' "$response" | device_field effective_source)
    expect_eq "$effective" "blocked" "USB storage must be blocked by DC policy" || return
    expect_eq "$source" "dc:block_usb_storage" "blocked USB storage source must be DC setting"
}

test_blocked_usb_not_visible_as_connected() {
    local response connected
    response=$(find_device_any_attr "ID_SERIAL,ID_SERIAL_SHORT,SERIAL" "$USB_BLOCKED_SERIAL") || return
    connected=$(printf '%s\n' "$response" | device_field connected)
    expect_eq "$connected" "False" "blocked USB storage should be marked disconnected after enforcement"
}

run_smoke_suite() {
    run_test "device IPC status responds" test_device_ipc_status
    run_test "device root can be read" test_device_root
    run_test "udev PCI retrigger is visible in device tree" test_udev_trigger_pci_seen
    run_test "virtio block disk is recorded as connected" test_attach_virtio_block_connected
    run_test "virtio block connect event is recorded" test_virtio_connect_event_recorded
    run_test "detached virtio block remains in disconnected history" test_detach_virtio_block_history
    run_test "detached virtio block is hidden from current tree" test_detached_virtio_hidden_from_current_tree
    run_test "USB storage is allowed while DC policy is disabled" test_attach_usb_storage_allowed
    run_test "USB storage is blocked when DC policy is enabled" test_attach_usb_storage_blocked_by_dc
    run_test "blocked USB storage is no longer connected" test_blocked_usb_not_visible_as_connected
}
