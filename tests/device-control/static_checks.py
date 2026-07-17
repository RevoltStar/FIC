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

    udev_source = read_text(udev_collector)
    require("/devices/virtual/block/" in udev_source, "virtual block devices must be accepted")

    return 0


if __name__ == "__main__":
    sys.exit(main())
