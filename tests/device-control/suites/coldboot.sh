#!/usr/bin/env bash

prepare_configured_usb_disk() {
    local image=$1
    local target=$2
    local serial=$3
    detach_disk "$target"
    detach_disk_config "$target"
    create_test_image "$image" || return
    attach_disk_config "$image" "$target" usb "$serial"
}

test_cold_boot_dc_policy_blocks_configured_usb_storage() {
    set_usb_storage_policy true >/dev/null || return
    prepare_configured_usb_disk "$USB_BLOCKED_DISK" "$USB_BLOCKED_TARGET" "$USB_BLOCKED_SERIAL" || return
    reboot_guest || return

    local response effective source connected
    response=$(wait_for_test_disk "$USB_BLOCKED_SERIAL" "/dev/$USB_BLOCKED_TARGET" "" 90) || {
        detach_disk "$USB_BLOCKED_TARGET"
        detach_disk_config "$USB_BLOCKED_TARGET"
        return 1
    }
    effective=$(printf '%s\n' "$response" | device_field effective_control_level)
    source=$(printf '%s\n' "$response" | device_field effective_source)
    connected=$(printf '%s\n' "$response" | device_field connected)
    detach_disk "$USB_BLOCKED_TARGET"
    detach_disk_config "$USB_BLOCKED_TARGET"
    expect_eq "$effective" "blocked" "configured USB storage must be blocked during cold boot" || return
    expect_eq "$source" "dc:block_usb_storage" "cold boot block source must be DC policy" || return
    expect_eq "$connected" "False" "cold boot blocked USB storage must be disconnected after enforcement"
}

test_cold_boot_explicit_block_rule_blocks_configured_usb_storage() {
    set_usb_storage_policy false >/dev/null || return
    detach_disk "$USB_ALLOWED_TARGET"
    detach_disk_config "$USB_ALLOWED_TARGET"
    create_test_image "$USB_ALLOWED_DISK" || return
    attach_disk "$USB_ALLOWED_DISK" "$USB_ALLOWED_TARGET" usb "$USB_ALLOWED_SERIAL" || return
    remote_sudo "udevadm settle --timeout=20" || return

    local response id effective source connected
    response=$(wait_for_test_disk "$USB_ALLOWED_SERIAL" "/dev/$USB_ALLOWED_TARGET" true 45) || return
    id=$(printf '%s\n' "$response" | device_field id)
    detach_disk "$USB_ALLOWED_TARGET"
    remote_sudo "udevadm settle --timeout=20" || return
    wait_for_test_disk "$USB_ALLOWED_SERIAL" "/dev/$USB_ALLOWED_TARGET" false 45 >/dev/null || return
    response=$(remote_sudo "python3 $(printf '%q' "$REMOTE_HELPER") set $id blocked") || return
    expect_eq "$(printf '%s\n' "$response" | json_field ok)" "True" "explicit cold boot block rule must be accepted" || return

    attach_disk_config "$USB_ALLOWED_DISK" "$USB_ALLOWED_TARGET" usb "$USB_ALLOWED_SERIAL" || {
        reset_device_id_path "$id"
        return 1
    }
    reboot_guest || {
        reset_device_id_path "$id"
        return 1
    }
    response=$(wait_for_test_disk "$USB_ALLOWED_SERIAL" "/dev/$USB_ALLOWED_TARGET" "" 90) || {
        reset_device_id_path "$id"
        detach_disk "$USB_ALLOWED_TARGET"
        detach_disk_config "$USB_ALLOWED_TARGET"
        return 1
    }
    effective=$(printf '%s\n' "$response" | device_field effective_control_level)
    source=$(printf '%s\n' "$response" | device_field effective_source)
    connected=$(printf '%s\n' "$response" | device_field connected)
    reset_device_id_path "$id"
    detach_disk "$USB_ALLOWED_TARGET"
    detach_disk_config "$USB_ALLOWED_TARGET"
    expect_eq "$effective" "blocked" "explicit rule must block configured USB storage during cold boot" || return
    expect_eq "$source" "placement:$id" "cold boot explicit block source must be the device placement" || return
    expect_eq "$connected" "False" "explicitly blocked cold boot USB storage must be disconnected"
}

run_coldboot_suite() {
    run_test "cold boot DC policy blocks configured USB storage" test_cold_boot_dc_policy_blocks_configured_usb_storage
    run_test "cold boot explicit block rule blocks configured USB storage" test_cold_boot_explicit_block_rule_blocks_configured_usb_storage
}
