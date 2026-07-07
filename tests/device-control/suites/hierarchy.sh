#!/usr/bin/env bash

ensure_hierarchy_usb_allowed_fixture() {
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

reset_device_id_best_effort() {
    local id=$1
    [[ -n "$id" && "$id" != "0" && "$id" != "-1" ]] || return 0
    remote_sudo "python3 $(printf '%q' "$REMOTE_HELPER") reset $id" >/dev/null 2>&1 || true
}

test_ignored_parent_is_inherited_by_child() {
    ensure_hierarchy_usb_allowed_fixture || return
    local child parent_id response effective ok
    child=$(find_device_any_attr "ID_SERIAL,ID_SERIAL_SHORT,SERIAL" "$USB_ALLOWED_SERIAL" true) || return
    parent_id=$(printf '%s\n' "$child" | device_field parent_id)
    [[ -n "$parent_id" && "$parent_id" != "0" && "$parent_id" != "-1" ]] ||
        fail "USB allowed fixture must have a parent_id"

    response=$(remote_sudo "python3 $(printf '%q' "$REMOTE_HELPER") set $parent_id ignored") || return
    ok=$(printf '%s\n' "$response" | json_field ok)
    if [[ "$ok" != "True" ]]; then
        reset_device_id_best_effort "$parent_id"
        fail "failed to mark parent ignored: $(printf '%s\n' "$response" | json_field message)"
        return
    fi

    response=$(device_ipc "{\"command\":\"device_get\",\"device_id\":$(printf '%s\n' "$child" | device_field id)}") || {
        reset_device_id_best_effort "$parent_id"
        return 1
    }
    effective=$(printf '%s\n' "$response" | device_field effective_control_level)
    reset_device_id_best_effort "$parent_id"
    expect_eq "$effective" "ignored" "child must inherit ignored effective policy from parent"
}

test_parent_reset_restores_child_default_effective_policy() {
    ensure_hierarchy_usb_allowed_fixture || return
    local child effective
    child=$(find_device_any_attr "ID_SERIAL,ID_SERIAL_SHORT,SERIAL" "$USB_ALLOWED_SERIAL" true) || return
    effective=$(printf '%s\n' "$child" | device_field effective_control_level)
    expect_eq "$effective" "allowed" "child effective policy must return to allowed after parent reset"
}

run_hierarchy_suite() {
    run_test "ignored parent policy is inherited by child" test_ignored_parent_is_inherited_by_child
    run_test "parent reset restores child default effective policy" test_parent_reset_restores_child_default_effective_policy
}
