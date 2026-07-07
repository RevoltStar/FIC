#!/usr/bin/env bash

ensure_security_usb_allowed_fixture() {
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

test_unprivileged_udev_event_is_rejected_or_denied() {
    local response ok message
    if ! response=$(device_ipc_user '{"command":"udev_event","action":"add","devpath":"/devices/fic-test-denied","subsystem":"usb","env":{}}' 2>&1); then
        [[ "$response" == *"Permission denied"* || "$response" == *"Отказано"* || "$response" == *"denied"* ]] ||
            fail "unexpected unprivileged udev_event transport failure: $response"
        return
    fi
    ok=$(printf '%s\n' "$response" | json_field ok)
    message=$(printf '%s\n' "$response" | json_field message)
    expect_eq "$ok" "False" "unprivileged udev_event must be rejected" || return
    [[ "$message" == *"udev_event requires root peer credentials"* ]] ||
        fail "unexpected unprivileged udev_event message: $message"
}

test_delete_connected_device_is_rejected() {
    ensure_security_usb_allowed_fixture || return
    local response id ok message
    response=$(find_device_any_attr "ID_SERIAL,ID_SERIAL_SHORT,SERIAL" "$USB_ALLOWED_SERIAL" true) || return
    id=$(printf '%s\n' "$response" | device_field id)
    response=$(device_ipc "{\"command\":\"device_delete\",\"device_id\":$id}") || return
    ok=$(printf '%s\n' "$response" | json_field ok)
    message=$(printf '%s\n' "$response" | json_field message)
    expect_eq "$ok" "False" "connected device delete must be rejected" || return
    [[ "$message" == *"only disconnected non-system device subtrees can be deleted"* ]] ||
        fail "unexpected connected delete message: $message"
}

test_delete_root_device_is_rejected() {
    local response id ok message
    response=$(device_ipc '{"command":"device_root"}') || return
    id=$(printf '%s\n' "$response" | device_field id)
    response=$(device_ipc "{\"command\":\"device_delete\",\"device_id\":$id}") || return
    ok=$(printf '%s\n' "$response" | json_field ok)
    message=$(printf '%s\n' "$response" | json_field message)
    expect_eq "$ok" "False" "root device delete must be rejected" || return
    [[ "$message" == *"only disconnected non-system device subtrees can be deleted"* ]] ||
        fail "unexpected root delete message: $message"
}

test_invalid_json_is_rejected() {
    local response ok message
    response=$(remote_sudo "python3 $(printf '%q' "$REMOTE_HELPER") invalid-json") || return
    ok=$(printf '%s\n' "$response" | json_field ok)
    message=$(printf '%s\n' "$response" | json_field message)
    expect_eq "$ok" "False" "invalid JSON must be rejected" || return
    [[ "$message" == *"invalid request"* ]] || fail "unexpected invalid JSON message: $message"
}

test_cli_preserves_daemon_error_text() {
    local output
    output=$(remote_sudo "$REMOTE_FIC_CLI device get 999999999 || true") || return
    [[ "$output" == *"device not found"* ]] ||
        fail "fic-cli must show daemon error text; output was: $output"
}

run_security_suite() {
    run_test "unprivileged udev_event is rejected or denied by socket permissions" test_unprivileged_udev_event_is_rejected_or_denied
    run_test "connected device delete is rejected" test_delete_connected_device_is_rejected
    run_test "root device delete is rejected" test_delete_root_device_is_rejected
    run_test "invalid JSON request is rejected" test_invalid_json_is_rejected
    run_test "CLI preserves daemon error text" test_cli_preserves_daemon_error_text
}
