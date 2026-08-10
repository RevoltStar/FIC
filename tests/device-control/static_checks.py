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
    gui_main_window = root / "fic-gui" / "src" / "mainwindow.cpp"
    fic_daemon = root / "fic" / "src" / "main.cpp"
    udev_trigger = root / "fic" / "src" / "scripts" / "service" / "fic-udevadm-trigger.in"
    udev_rules = root / "fic" / "src" / "scripts" / "udev" / "99-fic-devices.rules.in"
    policy_compiler = root / "fic-dick" / "src" / "core" / "DevicePolicyCompiler.cpp"
    device_enforcer = root / "fic-dick" / "src" / "core" / "DeviceEnforcer.cpp"

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
    for marker in [
        "device_tree_state",
        "device_tree_revision_devices_insert",
        "device_tree_revision_attributes_insert",
        "device_tree_revision_events_insert",
        "getDeviceTreeRevision",
        "children_control",
        "device_policy_state",
        "desired_revision",
        "active_revision",
        "ALTER TABLE devices ADD COLUMN children_control",
    ]:
        require(marker in db_source, f"missing device tree revision support: {marker}")

    daemon_source = read_text(device_daemon)
    for marker in [
        "udev_event requires root peer credentials",
        "peer_credentials",
        "device_audit_",
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
    require("if (!write_reconcile_marker())" in daemon_source,
            "reconciliation marker result must be checked before udev helper returns success")
    require("ModuleConfigFileHandler" not in daemon_source,
            "device policy compiler runtime must use SQLite as desired-policy source")
    require("getDeviceCategoryPolicyState" in daemon_source,
            "device daemon must read category desired policy from devices.db")
    fic_daemon_source = read_text(fic_daemon)
    require('"device_regenerate_policy"' in fic_daemon_source,
            "fic daemon must synchronize DC policy changes with device desired state")
    event_handler = daemon_source[
        daemon_source.find("json process_device_event"):
        daemon_source.find("json handle_udev_event")
    ]
    require("enforce_block(" not in event_handler and "enforce_allow(" not in event_handler,
            "runtime inventory handler must not make SQLite-based hotplug enforcement decisions")

    compiler_source = read_text(policy_compiler)
    for marker in [
        "# INHERITED RULES",
        "# DIRECT PLACEMENT RULES",
        "# DIRECT IDENTITY RULES",
        "FIC_DIRECT_MATCH",
        "FIC_INHERITED_LEVEL",
        "DevicePolicyActivator::activate",
        "--reload-rules",
        "escapeUdevValue",
    ]:
        require(marker in compiler_source, f"missing generated device policy support: {marker}")
    require("DB" not in read_text(device_enforcer),
            "hotplug sysfs enforcer must not depend on the device database")

    gui_source = read_text(gui_tree)
    require('"device_tree_revision"' in gui_source,
            "GUI device polling must query the device tree revision")
    require("this, &DeviceTree::refreshIfTreeChanged" in gui_source,
            "GUI refresh timer must not rebuild the tree unconditionally")
    require("treeWidget->setMinimumWidth(640)" not in gui_source and
            "setMinimumWidth(660)" not in gui_source,
            "device tree must remain horizontally shrinkable")

    gui_main_source = read_text(gui_main_window)
    require("gridLayoutListView->addWidget(policyEditor, 0, 0)" in gui_main_source,
            "device policy editor must have a dedicated layout row")
    require("gridLayout_11->addWidget(deviceControlCombo" not in gui_main_source and
            "gridLayout_11->addWidget(deviceChildrenControlCombo" not in gui_main_source,
            "device policy controls must not share the read-only status layout")
    require("setColumnMinimumWidth(0, 660)" not in gui_main_source,
            "device page must not force the old overlapping 660 px tree column")

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
    require("trigger --action" not in trigger_source,
            "boot device inventory must not synthesize add events")
    require("fic-dick reconcile" in trigger_source,
            "boot helper must request authoritative reconciliation")

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

    require("wait-daemon 60" in trigger_source,
            "boot helper must wait for completed device-daemon startup")

    require(
        "lastErrno == ENOENT || lastErrno == ENOTDIR" in daemon_source,
        "missing udev event socket must be treated as daemon-unavailable startup state",
    )

    require(
        "if (lastErrno == ENOENT || lastErrno == ENOTDIR)" in daemon_source,
        "ENOENT/ENOTDIR handling must occur before reconciliation-marker fallback",
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
