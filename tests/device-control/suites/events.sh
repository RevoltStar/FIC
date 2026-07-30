#!/usr/bin/env bash

ensure_event_virtio_fixture() {
    if find_device_attr DEVNAME "/dev/$VIRTIO_TARGET" true >/dev/null 2>&1; then
        return 0
    fi
    detach_disk "$VIRTIO_TARGET"
    create_test_image "$VIRTIO_DISK" || return
    attach_disk "$VIRTIO_DISK" "$VIRTIO_TARGET" virtio "$VIRTIO_SERIAL" || return
    remote_sudo "udevadm settle --timeout=20" || return
    wait_for_attr DEVNAME "/dev/$VIRTIO_TARGET" true 30 >/dev/null
}

ensure_blocked_usb_fixture() {
    set_usb_storage_policy true >/dev/null || return
    reset_test_device_controls
    detach_disk "$USB_BLOCKED_TARGET"
    create_test_image "$USB_BLOCKED_DISK" || return
    attach_disk "$USB_BLOCKED_DISK" "$USB_BLOCKED_TARGET" usb "$USB_BLOCKED_SERIAL" || return
    remote_sudo "udevadm settle --timeout=20" || true
    wait_for_test_disk "$USB_BLOCKED_SERIAL" "/dev/$USB_BLOCKED_TARGET" "" 45 >/dev/null
}

test_virtio_connect_event_recorded_events_suite() {
    ensure_event_virtio_fixture || return
    local response id events count
    response=$(find_device_attr DEVNAME "/dev/$VIRTIO_TARGET" true) || return
    id=$(printf '%s\n' "$response" | device_field id)
    events=$(remote_sudo "python3 $(printf '%q' "$REMOTE_HELPER") events $id 20") || return
    count=$(printf '%s\n' "$events" | python3 -c 'import json,sys; data=json.load(sys.stdin); print(sum(1 for e in data.get("events", []) if e.get("event_type") == "connect"))')
    [[ "$count" -ge 1 ]] || fail "virtio block must have at least one connect event"
}

test_device_events_limit_is_respected() {
    ensure_event_virtio_fixture || return
    local response id events count
    response=$(find_device_attr DEVNAME "/dev/$VIRTIO_TARGET" true) || return
    id=$(printf '%s\n' "$response" | device_field id)
    events=$(remote_sudo "python3 $(printf '%q' "$REMOTE_HELPER") events $id 1") || return
    count=$(printf '%s\n' "$events" | python3 -c 'import json,sys; print(len(json.load(sys.stdin).get("events", [])))')
    [[ "$count" -le 1 ]] || fail "device_events limit=1 returned $count events"
}

test_blocked_usb_block_event_recorded_events_suite() {
    ensure_blocked_usb_fixture || return
    local response id events count
    response=$(find_device_any_attr "ID_SERIAL,ID_SERIAL_SHORT,SERIAL,DEVNAME" "$USB_BLOCKED_SERIAL") || {
        response=$(find_device_attr DEVNAME "/dev/$USB_BLOCKED_TARGET") || return
    }
    id=$(printf '%s\n' "$response" | device_field id)
    events=$(remote_sudo "python3 $(printf '%q' "$REMOTE_HELPER") events $id 20") || return
    count=$(printf '%s\n' "$events" | python3 -c 'import json,sys; data=json.load(sys.stdin); print(sum(1 for e in data.get("events", []) if e.get("event_type") == "block"))')
    [[ "$count" -ge 1 ]] || fail "blocked USB storage must have a block event"
}

test_global_block_events_can_be_filtered() {
    ensure_blocked_usb_fixture || return
    local events count
    events=$(device_ipc '{"command":"device_events","event_type":"block","limit":5}') || return
    count=$(printf '%s\n' "$events" | python3 -c 'import json,sys; data=json.load(sys.stdin); print(sum(1 for e in data.get("events", []) if e.get("event_type") == "block"))')
    [[ "$count" -ge 1 ]] || fail "global block event filter must return at least one block event"
}

test_blocked_usb_connect_precedes_block_event() {
    ensure_blocked_usb_fixture || return
    local response id events order
    response=$(find_device_any_attr "ID_SERIAL,ID_SERIAL_SHORT,SERIAL,DEVNAME" "$USB_BLOCKED_SERIAL") || {
        response=$(find_device_attr DEVNAME "/dev/$USB_BLOCKED_TARGET") || return
    }
    id=$(printf '%s\n' "$response" | device_field id)
    events=$(remote_sudo "python3 $(printf '%q' "$REMOTE_HELPER") events $id 50") || return
    order=$(printf '%s\n' "$events" | python3 -c '
import json, sys
items = json.load(sys.stdin).get("events", [])
items = sorted(items, key=lambda e: (e.get("created_at", ""), e.get("id", 0)))
connect = next((i for i, e in enumerate(items) if e.get("event_type") == "connect"), None)
block = next((i for i, e in enumerate(items) if e.get("event_type") == "block"), None)
print("ok" if connect is not None and block is not None and connect <= block else "bad")
')
    expect_eq "$order" "ok" "blocked USB connect event must precede block event"
}

run_events_suite() {
    run_test "virtio connect event is recorded" test_virtio_connect_event_recorded_events_suite
    run_test "device_events limit is respected" test_device_events_limit_is_respected
    run_test "blocked USB storage produces a block event" test_blocked_usb_block_event_recorded_events_suite
    run_test "global block events can be filtered" test_global_block_events_can_be_filtered
    run_test "blocked USB connect event precedes block event" test_blocked_usb_connect_precedes_block_event
}
