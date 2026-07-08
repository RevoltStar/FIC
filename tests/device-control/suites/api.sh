#!/usr/bin/env bash

ensure_disconnected_virtio_fixture() {
    if find_device_attr DEVNAME "/dev/$VIRTIO_TARGET" false >/dev/null 2>&1; then
        return 0
    fi
    detach_disk "$VIRTIO_TARGET"
    create_test_image "$VIRTIO_DISK" || return
    attach_disk "$VIRTIO_DISK" "$VIRTIO_TARGET" virtio "$VIRTIO_SERIAL" || return
    remote_sudo "udevadm settle --timeout=20" || return
    wait_for_attr DEVNAME "/dev/$VIRTIO_TARGET" true 30 >/dev/null || return
    detach_disk "$VIRTIO_TARGET"
    remote_sudo "udevadm settle --timeout=20" || return
    wait_for_attr DEVNAME "/dev/$VIRTIO_TARGET" false 30 >/dev/null
}

ensure_usb_allowed_fixture() {
    set_usb_storage_policy false false >/dev/null || return
    local response
    if response=$(find_device_any_attr "ID_SERIAL,ID_SERIAL_SHORT,SERIAL" "$USB_ALLOWED_SERIAL" true 2>/dev/null); then
        reset_device_from_response "$response"
        return 0
    fi
    detach_disk "$USB_ALLOWED_TARGET"
    create_test_image "$USB_ALLOWED_DISK" || return
    attach_disk "$USB_ALLOWED_DISK" "$USB_ALLOWED_TARGET" usb "$USB_ALLOWED_SERIAL" || return
    remote_sudo "udevadm settle --timeout=20" || return
    response=$(wait_for_test_disk "$USB_ALLOWED_SERIAL" "/dev/$USB_ALLOWED_TARGET" true 45) || return
    reset_device_from_response "$response"
}

test_explicit_rule_on_disconnected_device() {
    ensure_disconnected_virtio_fixture || return
    local response id set_response reset_response explicit
    response=$(find_device_attr DEVNAME "/dev/$VIRTIO_TARGET" false) || return
    id=$(printf '%s\n' "$response" | device_field id)
    set_response=$(remote_sudo "python3 $(printf '%q' "$REMOTE_HELPER") set $id allowed") || return
    explicit=$(printf '%s\n' "$set_response" | device_field control_explicit)
    expect_eq "$explicit" "True" "device set allowed must make rule explicit" || return
    reset_response=$(remote_sudo "python3 $(printf '%q' "$REMOTE_HELPER") reset $id") || return
    explicit=$(printf '%s\n' "$reset_response" | device_field control_explicit)
    expect_eq "$explicit" "False" "device reset must restore inheritance"
}

test_disconnected_device_cannot_be_permanent() {
    ensure_disconnected_virtio_fixture || return
    local response id ok message
    response=$(find_device_attr DEVNAME "/dev/$VIRTIO_TARGET" false) || return
    id=$(printf '%s\n' "$response" | device_field id)
    response=$(device_ipc "{\"command\":\"device_update_control_level\",\"device_id\":$id,\"control_level\":\"permanent\"}") || return
    ok=$(printf '%s\n' "$response" | json_field ok)
    message=$(printf '%s\n' "$response" | json_field message)
    expect_eq "$ok" "False" "disconnected device must not be marked permanent" || return
    [[ "$message" == *"cannot mark absent device as permanent"* ]] ||
        fail "unexpected permanent rejection message: $message"
}

test_disconnected_device_subtree_can_be_deleted() {
    ensure_disconnected_virtio_fixture || return
    local response id ok message
    response=$(find_device_attr DEVNAME "/dev/$VIRTIO_TARGET" false) || return
    id=$(printf '%s\n' "$response" | device_field id)
    response=$(remote_sudo "python3 $(printf '%q' "$REMOTE_HELPER") delete $id") || return
    ok=$(printf '%s\n' "$response" | json_field ok)
    expect_eq "$ok" "True" "disconnected virtio subtree delete must succeed" || return
    response=$(device_ipc "{\"command\":\"device_get\",\"device_id\":$id}") || return
    ok=$(printf '%s\n' "$response" | json_field ok)
    message=$(printf '%s\n' "$response" | json_field message)
    expect_eq "$ok" "False" "deleted disconnected virtio device id must not remain readable" || return
    [[ "$message" == *"device not found"* ]] ||
        fail "unexpected deleted device_get message: $message"
}

test_usb_storage_attributes_include_serial() {
    ensure_usb_allowed_fixture || return
    local response id_bus serial matched
    response=$(find_device_any_attr "ID_SERIAL,ID_SERIAL_SHORT,SERIAL" "$USB_ALLOWED_SERIAL" true) || return
    id_bus=$(printf '%s\n' "$response" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("attributes", {}).get("ID_BUS", ""))')
    serial=$(printf '%s\n' "$response" | python3 -c 'import json,sys; data=json.load(sys.stdin); attrs=data.get("attributes", {}); print(attrs.get("ID_SERIAL") or attrs.get("ID_SERIAL_SHORT") or attrs.get("SERIAL", ""))')
    matched=$(printf '%s\n' "$response" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("matched_attribute", ""))')
    expect_eq "$id_bus" "usb" "USB allowed disk must keep ID_BUS=usb" || return
    [[ "$serial" == *"$USB_ALLOWED_SERIAL"* ]] ||
        fail "USB allowed disk serial attributes must contain $USB_ALLOWED_SERIAL; matched=$matched serial=$serial"
}

test_invalid_control_level_is_rejected() {
    ensure_usb_allowed_fixture || return
    local response id ok message
    response=$(find_device_any_attr "ID_SERIAL,ID_SERIAL_SHORT,SERIAL" "$USB_ALLOWED_SERIAL" true) || return
    id=$(printf '%s\n' "$response" | device_field id)
    response=$(device_ipc "{\"command\":\"device_update_control_level\",\"device_id\":$id,\"control_level\":\"definitely_invalid\"}") || return
    ok=$(printf '%s\n' "$response" | json_field ok)
    message=$(printf '%s\n' "$response" | json_field message)
    expect_eq "$ok" "False" "invalid control_level must be rejected" || return
    [[ "$message" == *"valid device_id and control_level are required"* ]] ||
        fail "unexpected invalid control_level message: $message"
}

test_invalid_ignore_hierarchy_is_rejected() {
    ensure_usb_allowed_fixture || return
    local response id ok message
    response=$(find_device_any_attr "ID_SERIAL,ID_SERIAL_SHORT,SERIAL" "$USB_ALLOWED_SERIAL" true) || return
    id=$(printf '%s\n' "$response" | device_field id)
    response=$(device_ipc "{\"command\":\"device_update_ignore_hierarchy\",\"device_id\":$id,\"ignore_hierarchy\":\"true\"}") || return
    ok=$(printf '%s\n' "$response" | json_field ok)
    message=$(printf '%s\n' "$response" | json_field message)
    expect_eq "$ok" "False" "string ignore_hierarchy must be rejected" || return
    [[ "$message" == *"device_id and boolean ignore_hierarchy are required"* ]] ||
        fail "unexpected ignore_hierarchy rejection message: $message"
}

test_connected_device_can_be_marked_permanent_and_reset() {
    ensure_usb_allowed_fixture || return
    local response id explicit effective reset_response
    response=$(find_device_any_attr "ID_SERIAL,ID_SERIAL_SHORT,SERIAL" "$USB_ALLOWED_SERIAL" true) || return
    id=$(printf '%s\n' "$response" | device_field id)
    response=$(remote_sudo "python3 $(printf '%q' "$REMOTE_HELPER") set $id permanent") || return
    explicit=$(printf '%s\n' "$response" | device_field control_explicit)
    effective=$(printf '%s\n' "$response" | device_field effective_control_level)
    expect_eq "$explicit" "True" "connected permanent rule must be explicit" || return
    expect_eq "$effective" "permanent" "connected device must become effectively permanent" || return
    reset_response=$(remote_sudo "python3 $(printf '%q' "$REMOTE_HELPER") reset $id") || return
    explicit=$(printf '%s\n' "$reset_response" | device_field control_explicit)
    expect_eq "$explicit" "False" "permanent test must reset device control"
}

test_missing_device_id_errors_are_clear() {
    local response ok message
    response=$(device_ipc '{"command":"device_get","device_id":999999999}') || return
    ok=$(printf '%s\n' "$response" | json_field ok)
    message=$(printf '%s\n' "$response" | json_field message)
    expect_eq "$ok" "False" "missing device_get id must fail" || return
    [[ "$message" == *"device not found"* ]] || fail "unexpected device_get missing id message: $message"
}

test_unknown_device_command_is_rejected() {
    local response ok message
    response=$(device_ipc '{"command":"device_totally_unknown"}') || return
    ok=$(printf '%s\n' "$response" | json_field ok)
    message=$(printf '%s\n' "$response" | json_field message)
    expect_eq "$ok" "False" "unknown device command must fail" || return
    [[ "$message" == *"unknown device command"* ]] || fail "unexpected unknown command message: $message"
}

run_api_suite() {
    run_test "explicit control can be set and reset on disconnected device" test_explicit_rule_on_disconnected_device
    run_test "disconnected device cannot be marked permanent" test_disconnected_device_cannot_be_permanent
    run_test "disconnected device subtree can be deleted" test_disconnected_device_subtree_can_be_deleted
    run_test "USB storage attributes include the test serial" test_usb_storage_attributes_include_serial
    run_test "invalid device control level is rejected" test_invalid_control_level_is_rejected
    run_test "invalid ignore_hierarchy payload is rejected" test_invalid_ignore_hierarchy_is_rejected
    run_test "connected device can be marked permanent and reset" test_connected_device_can_be_marked_permanent_and_reset
    run_test "missing device id errors are clear" test_missing_device_id_errors_are_clear
    run_test "unknown device command is rejected" test_unknown_device_command_is_rejected
}
