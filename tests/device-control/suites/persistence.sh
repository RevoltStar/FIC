#!/usr/bin/env bash

ensure_persistence_usb_fixture() {
    set_usb_storage_policy false >/dev/null || return
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

test_explicit_control_persists_after_device_daemon_restart() {
    ensure_persistence_usb_fixture || return
    local response id effective explicit
    response=$(find_device_any_attr "ID_SERIAL,ID_SERIAL_SHORT,SERIAL" "$USB_ALLOWED_SERIAL" true) || return
    id=$(printf '%s\n' "$response" | device_field id)
    response=$(remote_sudo "python3 $(printf '%q' "$REMOTE_HELPER") set $id permanent") || return
    effective=$(printf '%s\n' "$response" | device_field effective_control_level)
    expect_eq "$effective" "permanent" "fixture must become permanent before daemon restart" || {
        reset_device_id_path "$id"
        return 1
    }
    restart_device_daemon || {
        reset_device_id_path "$id"
        return 1
    }
    response=$(device_ipc "{\"command\":\"device_get\",\"device_id\":$id}") || {
        reset_device_id_path "$id"
        return 1
    }
    effective=$(printf '%s\n' "$response" | device_field effective_control_level)
    explicit=$(printf '%s\n' "$response" | device_field control_explicit)
    reset_device_id_path "$id"
    expect_eq "$effective" "permanent" "explicit control must survive fic-device restart" || return
    expect_eq "$explicit" "True" "explicit flag must survive fic-device restart"
}

test_disconnected_block_rule_persists_after_device_daemon_restart() {
    ensure_persistence_usb_fixture || return
    local response id effective explicit
    response=$(find_device_any_attr "ID_SERIAL,ID_SERIAL_SHORT,SERIAL" "$USB_ALLOWED_SERIAL" true) || return
    id=$(printf '%s\n' "$response" | device_field id)
    detach_disk "$USB_ALLOWED_TARGET"
    remote_sudo "udevadm settle --timeout=20" || return
    wait_for_test_disk "$USB_ALLOWED_SERIAL" "/dev/$USB_ALLOWED_TARGET" false 45 >/dev/null || return
    response=$(remote_sudo "python3 $(printf '%q' "$REMOTE_HELPER") set $id blocked") || return
    expect_eq "$(printf '%s\n' "$response" | json_field ok)" "True" "disconnected block rule must be accepted" || return
    restart_device_daemon || {
        reset_device_id_path "$id"
        return 1
    }
    response=$(device_ipc "{\"command\":\"device_get\",\"device_id\":$id}") || {
        reset_device_id_path "$id"
        return 1
    }
    effective=$(printf '%s\n' "$response" | device_field effective_control_level)
    explicit=$(printf '%s\n' "$response" | device_field control_explicit)
    reset_device_id_path "$id"
    expect_eq "$effective" "blocked" "disconnected block rule must survive fic-device restart" || return
    expect_eq "$explicit" "True" "disconnected block rule must remain explicit after restart"
}

test_device_events_persist_after_device_daemon_restart() {
    ensure_persistence_usb_fixture || return
    local response id before after
    response=$(find_device_any_attr "ID_SERIAL,ID_SERIAL_SHORT,SERIAL" "$USB_ALLOWED_SERIAL" true) || return
    id=$(printf '%s\n' "$response" | device_field id)
    before=$(device_event_count "$id" connect)
    restart_device_daemon || return
    after=$(device_event_count "$id" connect)
    [[ "$after" -ge "$before" && "$after" -ge 1 ]] ||
        fail "connect event history must survive fic-device restart: before=$before after=$after"
}

test_policy_state_persists_after_fic_daemon_restart() {
    set_usb_storage_policy true >/dev/null || return
    restart_fic_daemon || return
    local enabled value
    enabled=$(remote_sudo "$REMOTE_FIC_CLI policy isenable DC block_usb_storage" | tail -n 1 | tr -d '\r')
    value=$(remote_sudo "$REMOTE_FIC_CLI policy value DC block_usb_storage" | tail -n 1 | tr -d '\r')
    expect_eq "$enabled" "true" "DC block_usb_storage enabled state must survive fic restart" || return
    expect_eq "$value" "true" "DC block_usb_storage fixed value must remain true after fic restart"
}

run_persistence_suite() {
    run_test "explicit device control persists after fic-device restart" test_explicit_control_persists_after_device_daemon_restart
    run_test "disconnected block rule persists after fic-device restart" test_disconnected_block_rule_persists_after_device_daemon_restart
    run_test "device event history persists after fic-device restart" test_device_events_persist_after_device_daemon_restart
    run_test "DC policy state persists after fic restart" test_policy_state_persists_after_fic_daemon_restart
}
