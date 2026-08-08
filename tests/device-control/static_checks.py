#!/usr/bin/env python3
import sqlite3
import sys
from pathlib import Path


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def read_text(path):
    return path.read_text(encoding="utf-8")


def main():
    if len(sys.argv) != 2:
        print("usage: static_checks.py <repo-root>", file=sys.stderr)
        return 2

    root = Path(sys.argv[1])
    db_path = root / "fic" / "src" / "scripts" / "db" / "devices.db"
    device_daemon = root / "fic-dick" / "src" / "core" / "DeviceControlDaemon.cpp"
    dc_policy = root / "fic" / "src" / "modules" / "dc" / "DC.cpp"
    dc_config = root / "fic" / "src" / "scripts" / "config" / "DC.conf"
    db_cpp = root / "fic-common" / "fic-device-db" / "src" / "DB.cpp"
    udev_collector = root / "fic-dick" / "src" / "modules" / "UDEVInfoCollector.cpp"
    gui_tree = root / "fic-gui" / "src" / "DeviceTree.cpp"
    udev_trigger = root / "fic" / "src" / "scripts" / "service" / "fic-udevadm-trigger.in"
    udev_rules = root / "fic" / "src" / "scripts" / "udev" / "99-fic-devices.rules.in"

    with sqlite3.connect(db_path) as connection:
        columns = [row[1] for row in connection.execute("PRAGMA table_info(devices)")]
        revision_rows = list(connection.execute(
            "SELECT revision FROM device_tree_state WHERE id = 1"
        ))
        revision_triggers = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type = 'trigger' AND name LIKE 'device_tree_revision_%'"
            )
        }
    require("control_explicit" in columns, "seed devices.db must contain control_explicit")
    require(revision_rows and revision_rows[0][0] >= 0,
            "seed devices.db must contain a non-negative device tree revision")
    require(len(revision_triggers) == 9,
            "seed devices.db must contain all device tree revision triggers")

    db_source = read_text(db_cpp)
    forbidden_migration_markers = [
        "ALTER TABLE",
        "RENAME COLUMN",
        "devices_new",
        "device_attributes_new",
        "device_events_new",
        "lock_history_new",
    ]
    for marker in forbidden_migration_markers:
        require(marker not in db_source, f"runtime DB migrations are not allowed: {marker}")
    for marker in [
        "device_tree_state",
        "device_tree_revision_devices_insert",
        "device_tree_revision_attributes_insert",
        "device_tree_revision_events_insert",
        "getDeviceTreeRevision",
    ]:
        require(marker in db_source, f"missing device tree revision support: {marker}")

    daemon_source = read_text(device_daemon)
    for marker in [
        "udev_event requires root peer credentials",
        "peer_credentials",
        "device_audit_",
        "retry_sysfs_action",
        "collect_missing_permanent_devices",
        "device_tree_revision",
        "SOCK_DGRAM",
        "SO_PASSCRED",
        "SCM_CREDENTIALS",
        "MAX_DEVICE_EVENT_QUEUE",
        "run_device_reconciliation",
        "fic-device-events.sock",
        "fic-device-reconcile.required",
    ]:
        require(marker in daemon_source, f"missing device daemon guard: {marker}")
    require("create_admin_server_socket" in daemon_source,
            "device daemon must use the shared guarded socket creator")
    require('fic::ipc::Client(socketPath).request({\\n        {"command", "udev_event"}' not in daemon_source,
            "fic-dick udev must not use synchronous administrative IPC")
    require("reconciliation marker could not be created" in daemon_source,
            "fic-dick udev must fail when an undelivered event cannot mark reconciliation")
    require("write_reconcile_marker(reason)" in daemon_source,
            "reconciliation marker result must be checked before udev helper returns success")
    require("dc_policy_enabled_and_true" not in daemon_source,
            "DC policy state must not depend on a configurable boolean value")
    require('config.getPolicyStatus(policy) == "ENABLE"' in daemon_source,
            "device daemon must use DC policy status as the only switch")

    gui_source = read_text(gui_tree)
    require('"device_tree_revision"' in gui_source,
            "GUI device polling must query the device tree revision")
    require("this, &DeviceTree::refreshIfTreeChanged" in gui_source,
            "GUI refresh timer must not rebuild the tree unconditionally")

    dc_policy_source = read_text(dc_policy)
    require('std::make_unique<FixedPolicyTypeValue>("true")' in dc_policy_source,
            "DC policies must expose the intrinsic fixed value true")
    require("PossibleListPolicyTypeValue" not in dc_policy_source,
            "DC policies must not expose a configurable true/false list")

    dc_config_values = {}
    for line in read_text(dc_config).splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            dc_config_values[key.strip()] = value.strip()
    for policy in [
        "block_usb_storage",
        "block_printers_scanners",
        "block_optical_drives",
    ]:
        require(dc_config_values.get(f"{policy}.value") == "true",
                f"{policy} seed value must match its intrinsic fixed value")

    udev_source = read_text(udev_collector)
    require("/devices/virtual/block/" in udev_source, "virtual block devices must be accepted")

    trigger_source = read_text(udev_trigger)
    require("udevadm" not in trigger_source,
            "boot device inventory must not depend on udevadm trigger")
    require("check-permanent" in trigger_source,
            "boot helper must still run permanent-device check")

    rules_source = read_text(udev_rules)
    require('RUN+="@FIC_PRIVATE_BINDIR@/fic-dick udev"' in rules_source,
            "udev rule must keep the short-lived fic-dick udev producer")

    require(
    "std::ios::app" not in daemon_source[
        daemon_source.find("bool write_reconcile_marker"):
        daemon_source.find("bool write_reconcile_marker") + 2500
    ],
    "reconciliation marker must not be an append-only event log",
    )

    require(
        "O_NOFOLLOW" in daemon_source,
        "reconciliation marker must reject symlink replacement",
    )

    require(
        "ftruncate(fd, 0)" in daemon_source,
        "reconciliation marker must remain bounded",
    )

    require(
        "create_directories(marker.parent_path())" not in daemon_source,
        "udev producer must not create the FIC runtime directory",
    )

    trigger_script = (
        root / "fic/src/scripts/service/fic-udevadm-trigger.in"
    ).read_text(encoding="utf-8")

    require(
        "check-permanent" not in trigger_script,
        "boot helper must not duplicate permanent check already owned by reconciliation",
    )

    require(
        "wait-daemon 15" in trigger_script,
        "boot helper must still wait for completed device-daemon startup",
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
