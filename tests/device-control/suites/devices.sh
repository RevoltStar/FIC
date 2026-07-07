#!/usr/bin/env bash

test_usb_hid_keyboard_is_recorded() {
    detach_device_xml "$USB_HID_XML"
    local baseline count
    baseline=$(count_subsystem usb true) || return
    attach_device_xml "$USB_HID_XML" || return
    remote_sudo "udevadm settle --timeout=20" || {
        detach_device_xml "$USB_HID_XML"
        return 1
    }
    count=$(wait_for_subsystem_count_gt usb "$baseline" true 30) || {
        detach_device_xml "$USB_HID_XML"
        return 1
    }
    detach_device_xml "$USB_HID_XML"
    [[ "$count" -gt "$baseline" ]] || fail "USB HID keyboard must add a connected usb device"
}

test_usb_tablet_input_is_recorded() {
    detach_device_xml "$USB_TABLET_XML"
    local before after new_name baseline count response
    before=$(sysfs_names /sys/class/input) || return
    baseline=$(count_subsystem input true) || return
    attach_device_xml "$USB_TABLET_XML" || return
    remote_sudo "udevadm settle --timeout=20" || {
        detach_device_xml "$USB_TABLET_XML"
        return 1
    }
    after=$(sysfs_names /sys/class/input) || {
        detach_device_xml "$USB_TABLET_XML"
        return 1
    }
    new_name=$(first_new_name "$before" "$after") || {
        detach_device_xml "$USB_TABLET_XML"
        fail "USB tablet hotplug did not create a new /sys/class/input entry"
        return 1
    }
    response=$(send_udev_from_sysfs add input "/sys/class/input/$new_name") || {
        detach_device_xml "$USB_TABLET_XML"
        printf '%s\n' "$response" >&2
        return 1
    }
    count=$(wait_for_subsystem_count_gt input "$baseline" true 30) || {
        detach_device_xml "$USB_TABLET_XML"
        return 1
    }
    detach_device_xml "$USB_TABLET_XML"
    [[ "$count" -gt "$baseline" ]] || fail "USB tablet must add a connected input device"
}

test_pci_virtio_rng_mock_is_recorded() {
    detach_device_xml "$PCI_RNG_XML"
    local baseline count
    baseline=$(count_subsystem pci true) || return
    attach_device_xml "$PCI_RNG_XML" || return
    remote_sudo "udevadm settle --timeout=20" || {
        detach_device_xml "$PCI_RNG_XML"
        return 1
    }
    count=$(wait_for_subsystem_count_gt pci "$baseline" true 30) || {
        detach_device_xml "$PCI_RNG_XML"
        return 1
    }
    detach_device_xml "$PCI_RNG_XML"
    [[ "$count" -gt "$baseline" ]] || fail "virtio RNG mock must add a connected PCI device"
}

test_cdrom_block_device_is_recorded() {
    detach_disk "$CDROM_TARGET"
    local baseline response id_type id_cdrom
    baseline=$(count_subsystem block true) || return
    attach_cdrom || return
    remote_sudo "udevadm settle --timeout=20" || {
        detach_disk "$CDROM_TARGET"
        return 1
    }
    wait_for_subsystem_count_gt block "$baseline" true 30 >/dev/null || {
        detach_disk "$CDROM_TARGET"
        return 1
    }
    response=$(wait_for_any_attr "ID_TYPE" "cd" true 10) || \
        response=$(wait_for_any_attr "ID_CDROM,ID_CDROM_CD" "1" true 10) || {
            detach_disk "$CDROM_TARGET"
            return 1
        }
    id_type=$(printf '%s\n' "$response" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("attributes", {}).get("ID_TYPE", ""))')
    id_cdrom=$(printf '%s\n' "$response" | python3 -c 'import json,sys; data=json.load(sys.stdin).get("attributes", {}); print(data.get("ID_CDROM") or data.get("ID_CDROM_CD") or "")')
    detach_disk "$CDROM_TARGET"
    [[ "$id_type" == "cd" || -n "$id_cdrom" ]] || fail "CD-ROM block device must expose CD-ROM udev attributes"
}

test_virtio_net_device_is_recorded() {
    detach_virtio_net
    local before after new_name baseline count response
    before=$(sysfs_names /sys/class/net) || return
    baseline=$(count_subsystem net true) || return
    attach_virtio_net || return
    remote_sudo "udevadm settle --timeout=20" || {
        detach_virtio_net
        return 1
    }
    after=$(sysfs_names /sys/class/net) || {
        detach_virtio_net
        return 1
    }
    new_name=$(first_new_name "$before" "$after") || {
        detach_virtio_net
        fail "virtio-net hotplug did not create a new /sys/class/net entry"
        return 1
    }
    response=$(send_udev_from_sysfs add net "/sys/class/net/$new_name") || {
        detach_virtio_net
        printf '%s\n' "$response" >&2
        return 1
    }
    count=$(wait_for_subsystem_count_gt net "$baseline" true 30) || {
        detach_virtio_net
        return 1
    }
    detach_virtio_net
    [[ "$count" -gt "$baseline" ]] || fail "virtio-net hotplug must add a connected net device"
}

test_virtio_serial_channel_is_recorded() {
    detach_device_xml "$SERIAL_CHANNEL_XML"
    local before tty_before after tty_after new_name baseline tty_baseline count response
    before=$(sysfs_names /sys/bus/virtio-ports/devices) || return
    tty_before=$(sysfs_names /sys/class/tty) || return
    baseline=$(count_subsystem virtio-ports true 2>/dev/null || printf '0')
    tty_baseline=$(count_subsystem tty true 2>/dev/null || printf '0')
    attach_device_xml "$SERIAL_CHANNEL_XML" || return
    remote_sudo "udevadm settle --timeout=20" || {
        detach_device_xml "$SERIAL_CHANNEL_XML"
        return 1
    }
    after=$(sysfs_names /sys/bus/virtio-ports/devices) || {
        detach_device_xml "$SERIAL_CHANNEL_XML"
        return 1
    }
    if new_name=$(first_new_name "$before" "$after" 2>/dev/null); then
        response=$(send_udev_from_sysfs add virtio-ports "/sys/bus/virtio-ports/devices/$new_name") || {
            detach_device_xml "$SERIAL_CHANNEL_XML"
            printf '%s\n' "$response" >&2
            return 1
        }
        count=$(wait_for_subsystem_count_gt virtio-ports "$baseline" true 30) || {
            detach_device_xml "$SERIAL_CHANNEL_XML"
            return 1
        }
        detach_device_xml "$SERIAL_CHANNEL_XML"
        [[ "$count" -gt "$baseline" ]] || fail "virtio serial channel must add a connected virtio-ports device"
        return
    fi

    tty_after=$(sysfs_names /sys/class/tty) || {
        detach_device_xml "$SERIAL_CHANNEL_XML"
        return 1
    }
    new_name=$(first_new_name "$tty_before" "$tty_after") || {
        detach_device_xml "$SERIAL_CHANNEL_XML"
        fail "virtio serial channel did not create a new virtio-ports or tty sysfs entry"
        return 1
    }
    response=$(send_udev_from_sysfs add tty "/sys/class/tty/$new_name") || {
        detach_device_xml "$SERIAL_CHANNEL_XML"
        printf '%s\n' "$response" >&2
        return 1
    }
    count=$(wait_for_subsystem_count_gt tty "$tty_baseline" true 10) || {
        detach_device_xml "$SERIAL_CHANNEL_XML"
        return 1
    }
    detach_device_xml "$SERIAL_CHANNEL_XML"
    [[ "$count" -gt "$tty_baseline" ]] || fail "serial hotplug must add a connected tty or virtio-ports device"
}

run_devices_suite() {
    run_test "USB HID keyboard is recorded" test_usb_hid_keyboard_is_recorded
    run_test "USB tablet input device is recorded" test_usb_tablet_input_is_recorded
    run_test "PCI virtio RNG mock is recorded" test_pci_virtio_rng_mock_is_recorded
    run_test "CD-ROM block device is recorded" test_cdrom_block_device_is_recorded
    run_test "virtio-net device is recorded" test_virtio_net_device_is_recorded
    run_test "virtio serial channel is recorded" test_virtio_serial_channel_is_recorded
}
