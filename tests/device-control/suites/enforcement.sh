#!/usr/bin/env bash

ensure_enforcement_usb_allowed_fixture() {
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

enforcement_attr() {
    local field=$1
    python3 -c 'import json,sys; print(json.load(sys.stdin).get("attributes", {}).get(sys.argv[1], ""))' "$field"
}

enforcement_device_get() {
    local id=$1
    device_ipc "{\"command\":\"device_get\",\"device_id\":$id}"
}

enforcement_reset_id() {
    local id=$1
    [[ -n "$id" && "$id" != "0" && "$id" != "-1" ]] || return 0
    remote_sudo "python3 $(printf '%q' "$REMOTE_HELPER") reset-path $id" >/dev/null 2>&1 || true
}

enforcement_event_count() {
    local id=$1
    local event_type=$2
    remote_sudo "python3 $(printf '%q' "$REMOTE_HELPER") events $id 50" |
        python3 -c 'import json,sys; data=json.load(sys.stdin); print(sum(1 for e in data.get("events", []) if e.get("event_type") == sys.argv[1]))' "$event_type"
}

test_explicit_allowed_effective_policy() {
    ensure_enforcement_usb_allowed_fixture || return
    local response id explicit effective source
    response=$(find_device_any_attr "ID_SERIAL,ID_SERIAL_SHORT,SERIAL" "$USB_ALLOWED_SERIAL" true) || return
    id=$(printf '%s\n' "$response" | device_field id)
    response=$(remote_sudo "python3 $(printf '%q' "$REMOTE_HELPER") set $id allowed") || return
    explicit=$(printf '%s\n' "$response" | device_field control_explicit)
    effective=$(printf '%s\n' "$response" | device_field effective_control_level)
    source=$(printf '%s\n' "$response" | device_field effective_source)
    enforcement_reset_id "$id"
    expect_eq "$explicit" "True" "allowed rule must be explicit" || return
    expect_eq "$effective" "allowed" "explicit allowed device must be effectively allowed" || return
    expect_eq "$source" "device:$id" "explicit allowed source must be the device itself"
}

test_explicit_blocked_reconnect_enforces_block() {
    ensure_enforcement_usb_allowed_fixture || return
    local response id effective source connected events
    response=$(find_device_any_attr "ID_SERIAL,ID_SERIAL_SHORT,SERIAL" "$USB_ALLOWED_SERIAL" true) || return
    id=$(printf '%s\n' "$response" | device_field id)
    detach_disk "$USB_ALLOWED_TARGET"
    remote_sudo "udevadm settle --timeout=20" || return
    wait_for_test_disk "$USB_ALLOWED_SERIAL" "/dev/$USB_ALLOWED_TARGET" false 45 >/dev/null || return
    response=$(remote_sudo "python3 $(printf '%q' "$REMOTE_HELPER") set $id blocked") || return
    expect_eq "$(printf '%s\n' "$response" | json_field ok)" "True" "setting blocked on disconnected device must succeed" || return
    attach_disk "$USB_ALLOWED_DISK" "$USB_ALLOWED_TARGET" usb "$USB_ALLOWED_SERIAL" || return
    remote_sudo "udevadm settle --timeout=20" || true
    response=$(wait_for_test_disk "$USB_ALLOWED_SERIAL" "/dev/$USB_ALLOWED_TARGET" "" 45) || {
        enforcement_reset_id "$id"
        return 1
    }
    effective=$(printf '%s\n' "$response" | device_field effective_control_level)
    source=$(printf '%s\n' "$response" | device_field effective_source)
    connected=$(printf '%s\n' "$response" | device_field connected)
    events=$(enforcement_event_count "$id" block)
    enforcement_reset_id "$id"
    detach_disk "$USB_ALLOWED_TARGET"
    expect_eq "$effective" "blocked" "explicit blocked device must be effectively blocked on reconnect" || return
    expect_eq "$source" "device:$id" "explicit blocked source must be the device itself" || return
    expect_eq "$connected" "False" "explicit blocked device must be disconnected after enforcement" || return
    [[ "$events" -ge 1 ]] || fail "explicit blocked reconnect must record a block event"
}

test_ignored_parent_overrides_blocked_child_on_reconnect() {
    ensure_enforcement_usb_allowed_fixture || return
    local child id parent_id response effective source connected
    child=$(find_device_any_attr "ID_SERIAL,ID_SERIAL_SHORT,SERIAL" "$USB_ALLOWED_SERIAL" true) || return
    id=$(printf '%s\n' "$child" | device_field id)
    parent_id=$(printf '%s\n' "$child" | device_field parent_id)
    [[ -n "$parent_id" && "$parent_id" != "0" && "$parent_id" != "-1" ]] ||
        fail "USB fixture must have a parent for ignored enforcement test" || return

    remote_sudo "python3 $(printf '%q' "$REMOTE_HELPER") set $parent_id ignored" >/dev/null || return
    remote_sudo "python3 $(printf '%q' "$REMOTE_HELPER") set $id blocked" >/dev/null || {
        enforcement_reset_id "$parent_id"
        return 1
    }
    detach_disk "$USB_ALLOWED_TARGET"
    remote_sudo "udevadm settle --timeout=20" || return
    attach_disk "$USB_ALLOWED_DISK" "$USB_ALLOWED_TARGET" usb "$USB_ALLOWED_SERIAL" || return
    remote_sudo "udevadm settle --timeout=20" || return
    response=$(wait_for_test_disk "$USB_ALLOWED_SERIAL" "/dev/$USB_ALLOWED_TARGET" true 45) || {
        enforcement_reset_id "$id"
        enforcement_reset_id "$parent_id"
        return 1
    }
    effective=$(printf '%s\n' "$response" | device_field effective_control_level)
    source=$(printf '%s\n' "$response" | device_field effective_source)
    connected=$(printf '%s\n' "$response" | device_field connected)
    enforcement_reset_id "$id"
    enforcement_reset_id "$parent_id"
    expect_eq "$effective" "ignored" "ignored parent must override blocked child rule" || return
    expect_eq "$source" "device:$parent_id" "ignored source must be the parent device" || return
    expect_eq "$connected" "True" "ignored device must remain connected because enforcement is skipped"
}

test_permanent_device_change_is_allowed() {
    ensure_enforcement_usb_allowed_fixture || return
    local response id devname effective events
    response=$(find_device_any_attr "ID_SERIAL,ID_SERIAL_SHORT,SERIAL" "$USB_ALLOWED_SERIAL" true) || return
    id=$(printf '%s\n' "$response" | device_field id)
    devname=$(printf '%s\n' "$response" | enforcement_attr DEVNAME)
    expect_nonempty "$devname" "permanent enforcement fixture must have DEVNAME" || return
    response=$(remote_sudo "python3 $(printf '%q' "$REMOTE_HELPER") set $id permanent") || return
    effective=$(printf '%s\n' "$response" | device_field effective_control_level)
    expect_eq "$effective" "permanent" "connected device must become permanent before change enforcement" || {
        enforcement_reset_id "$id"
        return 1
    }
    remote_sudo "udevadm trigger --action=change --name-match=$(printf '%q' "$devname")" || {
        enforcement_reset_id "$id"
        return 1
    }
    remote_sudo "udevadm settle --timeout=20" || return
    response=$(enforcement_device_get "$id") || return
    effective=$(printf '%s\n' "$response" | device_field effective_control_level)
    events=$(enforcement_event_count "$id" allow)
    enforcement_reset_id "$id"
    expect_eq "$effective" "permanent" "permanent device must remain effectively permanent after change event" || return
    [[ "$events" -ge 1 ]] || fail "permanent change event must record allow enforcement"
}

test_parent_allowed_rule_is_inherited() {
    ensure_enforcement_usb_allowed_fixture || return
    local child id parent_id response effective source
    child=$(find_device_any_attr "ID_SERIAL,ID_SERIAL_SHORT,SERIAL" "$USB_ALLOWED_SERIAL" true) || return
    id=$(printf '%s\n' "$child" | device_field id)
    parent_id=$(printf '%s\n' "$child" | device_field parent_id)
    [[ -n "$parent_id" && "$parent_id" != "0" && "$parent_id" != "-1" ]] ||
        fail "USB fixture must have a parent for inheritance test" || return
    enforcement_reset_id "$id"
    remote_sudo "python3 $(printf '%q' "$REMOTE_HELPER") set $parent_id allowed" >/dev/null || return
    response=$(enforcement_device_get "$id") || {
        enforcement_reset_id "$parent_id"
        return 1
    }
    effective=$(printf '%s\n' "$response" | device_field effective_control_level)
    source=$(printf '%s\n' "$response" | device_field effective_source)
    enforcement_reset_id "$parent_id"
    expect_eq "$effective" "allowed" "child must inherit allowed from parent" || return
    expect_eq "$source" "parent:$parent_id" "allowed inheritance source must be nearest parent"
}

test_grandparent_ignored_rule_is_inherited() {
    ensure_enforcement_usb_allowed_fixture || return
    local child id parent_id grandparent_id response effective source
    child=$(find_device_any_attr "ID_SERIAL,ID_SERIAL_SHORT,SERIAL" "$USB_ALLOWED_SERIAL" true) || return
    id=$(printf '%s\n' "$child" | device_field id)
    parent_id=$(printf '%s\n' "$child" | device_field parent_id)
    [[ -n "$parent_id" && "$parent_id" != "0" && "$parent_id" != "-1" ]] ||
        fail "USB fixture must have a parent for grandparent inheritance test" || return
    response=$(enforcement_device_get "$parent_id") || return
    grandparent_id=$(printf '%s\n' "$response" | device_field parent_id)
    [[ -n "$grandparent_id" && "$grandparent_id" != "0" && "$grandparent_id" != "-1" ]] ||
        fail "USB fixture parent must have a grandparent for inheritance test" || return

    enforcement_reset_id "$id"
    enforcement_reset_id "$parent_id"
    remote_sudo "python3 $(printf '%q' "$REMOTE_HELPER") set $grandparent_id ignored" >/dev/null || return
    response=$(enforcement_device_get "$id") || {
        enforcement_reset_id "$grandparent_id"
        return 1
    }
    effective=$(printf '%s\n' "$response" | device_field effective_control_level)
    source=$(printf '%s\n' "$response" | device_field effective_source)
    enforcement_reset_id "$grandparent_id"
    expect_eq "$effective" "ignored" "child must inherit ignored from grandparent" || return
    expect_eq "$source" "device:$grandparent_id" "ignored inheritance source must be the grandparent"
}

run_enforcement_suite() {
    run_test "explicit allowed policy is effective" test_explicit_allowed_effective_policy
    run_test "explicit blocked policy enforces block on reconnect" test_explicit_blocked_reconnect_enforces_block
    run_test "ignored parent overrides blocked child on reconnect" test_ignored_parent_overrides_blocked_child_on_reconnect
    run_test "permanent device change is allowed" test_permanent_device_change_is_allowed
    run_test "parent allowed rule is inherited" test_parent_allowed_rule_is_inherited
    run_test "grandparent ignored rule is inherited" test_grandparent_ignored_rule_is_inherited
}
