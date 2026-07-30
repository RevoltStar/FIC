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

    with sqlite3.connect(db_path) as connection:
        columns = [row[1] for row in connection.execute("PRAGMA table_info(devices)")]
    require("control_explicit" in columns, "seed devices.db must contain control_explicit")

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

    daemon_source = read_text(device_daemon)
    for marker in [
        "udev_event requires root peer credentials",
        "peer_credentials",
        "device_audit_",
        "retry_sysfs_action",
        "collect_missing_permanent_devices",
    ]:
        require(marker in daemon_source, f"missing device daemon guard: {marker}")
    require("create_admin_server_socket" in daemon_source,
            "device daemon must use the shared guarded socket creator")
    require("dc_policy_enabled_and_true" not in daemon_source,
            "DC policy state must not depend on a configurable boolean value")
    require('config.getPolicyStatus(policy) == "ENABLE"' in daemon_source,
            "device daemon must use DC policy status as the only switch")

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

    return 0


if __name__ == "__main__":
    sys.exit(main())
