#!/usr/bin/env python3
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
    device_daemon = root / "fic-dick" / "src" / "daemon" / "DeviceControlDaemon.cpp"
    device_snapshot = root / "fic-dick" / "src" / "device" / "DeviceTreeSnapshot.cpp"
    dc_policy = root / "fic" / "src" / "modules" / "dc" / "DC.cpp"
    dc_config = root / "fic" / "src" / "resources" / "config" / "DC.conf"
    db_cpp = root / "fic-common" / "fic-device-db" / "src" / "DB.cpp"
    udev_collector = root / "fic-dick" / "src" / "collectors" / "UDEVInfoCollector.cpp"
    gui_tree = root / "fic-gui" / "src" / "features" / "devices" / "widgets" / "DeviceTree.cpp"
    gui_device_page = root / "fic-gui" / "src" / "features" / "devices" / "pages" / "DeviceModulePage.cpp"
    fic_daemon = root / "fic" / "src" / "main.cpp"
    udev_trigger = root / "fic" / "src" / "resources" / "service" / "fic-udevadm-trigger.in"
    udev_rules = root / "fic" / "src" / "resources" / "udev" / "99-fic-devices.rules.in"
    policy_compiler = root / "fic-dick" / "src" / "policy" / "DevicePolicyCompiler.cpp"
    device_enforcer = root / "fic-dick" / "src" / "enforcement" / "DeviceEnforcer.cpp"
    device_enforcer_sysfs = root / "fic-dick" / "src" / "enforcement" / "DeviceEnforcerSysfs.cpp"
    device_lifecycle = root / "fic-dick" / "src" / "device" / "DeviceLifecycle.cpp"

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
    ]:
        require(marker in db_source, f"missing device tree revision support: {marker}")
    for obsolete in [
        "migrateDatabase",
        "LEGACY_CLEANUP_SQL",
        "allowLegacyTables",
        "ALTER TABLE devices ADD COLUMN children_control",
    ]:
        require(obsolete not in db_source,
                f"obsolete device database migration remains: {obsolete}")
    require(not (root / "fic/src/resources/db/devices.db").exists(),
            "pre-versioned device database fixture must not be shipped")

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
    snapshot_source = read_text(device_snapshot)
    require('command == "device_tree_snapshot"' in daemon_source,
            "device daemon must expose the flat device tree snapshot command")
    require("getDeviceTreeSnapshot" in snapshot_source,
            "snapshot command must use the database batch snapshot")
    for forbidden in [
        "getDeviceById(",
        "getDeviceAttributes(",
        "getDevicesByHashAndSubsystem(",
    ]:
        require(forbidden not in snapshot_source,
                f"snapshot effective-policy evaluation must not issue per-device DB calls: {forbidden}")
    require("WITH RECURSIVE tree" in db_source and
            "LEFT JOIN device_attributes" in db_source and
            "BEGIN TRANSACTION" in db_source,
            "database snapshot must read the recursive tree and attributes transactionally")
    fic_daemon_source = read_text(fic_daemon)
    require('"device_regenerate_policy"' in fic_daemon_source,
            "fic daemon must synchronize DC policy changes with device desired state")
    event_handler = daemon_source[
        daemon_source.find("json process_device_event"):
        daemon_source.find("json handle_udev_event")
    ]
    require("enforce_block(" not in event_handler and "enforce_allow(" not in event_handler,
            "runtime inventory handler must not make SQLite-based hotplug enforcement decisions")
    require("reset_subtree_boot_id" not in event_handler,
            "successful DENY must not clear device presence")
    require("safe_remove_device" not in event_handler,
            "remove must use exact current-boot lifecycle operation")
    require("removeCurrentOccurrence" in event_handler,
            "remove must select and mutate one current-boot occurrence")
    require("enforcementExpected = false" in daemon_source,
            "synthetic reconciliation events must not claim enforcement was attempted")

    lifecycle_source = read_text(device_lifecycle)
    for marker in [
        "DeviceRemovalResult",
        "getDeviceByDevpathSubsystemAndBootId",
        "disconnectCurrentSubtree",
        "alreadyRemoved",
        "beginTransaction",
    ]:
        require(marker in lifecycle_source, f"missing device lifecycle guard: {marker}")
    require("device absent during reconciliation" in daemon_source,
            "reconciliation must record why a current occurrence was disconnected")
    require("getDeviceByDevpathAndSubsystem" not in lifecycle_source,
            "remove lifecycle must not fall back to an arbitrary historical occurrence")

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
    enforcer_source = read_text(device_enforcer)
    enforcer_sysfs_source = read_text(device_enforcer_sysfs)
    require("DB" not in enforcer_source and "DB" not in enforcer_sysfs_source,
            "hotplug sysfs enforcer must not depend on the device database")
    require("enforced ? logLevel::INFO : logLevel::ERROR" in enforcer_source,
            "successful DENY enforcement must be INFO and failures must be ERROR")
    require('subsystem == "block" || subsystem == "pci"' not in enforcer_sysfs_source,
            "block DENY must never share the PCI remove fallback")
    require("findScsiDeleteTarget" in enforcer_sysfs_source and
            'sysfsSubsystemMatches(parent, "scsi", options)' in enforcer_sysfs_source,
            "block DENY must accept only a subsystem-verified SCSI delete target")
    require("findPciRemoveTarget" in enforcer_sysfs_source and
            'sysfsSubsystemMatches(devicePath.value(), "pci", options)' in enforcer_sysfs_source,
            "PCI DENY must accept only a subsystem-verified PCI remove target")
    require("PCI remove fallback is prohibited" in enforcer_sysfs_source,
            "block DENY without a safe target must fail closed")
    require('filename() == "device"' not in enforcer_sysfs_source,
            "SCSI delete validation must not rely on an invalid directory-name heuristic")

    gui_source = read_text(gui_tree)
    require('"device_tree_revision"' in gui_source,
            "GUI device polling must query the device tree revision")
    require("this, &DeviceTree::refreshIfTreeChanged" in gui_source,
            "GUI refresh timer must not rebuild the tree unconditionally")
    require('"device_tree_snapshot"' in gui_source,
            "GUI full-tree operations must use the flat snapshot command")
    filter_body = gui_source[
        gui_source.find("void DeviceTree::applyDeviceFilter"):
        gui_source.find("QIcon DeviceTree::deviceIcon")
    ]
    expand_body = gui_source[
        gui_source.find("void DeviceTree::expandAllNodes"):
        gui_source.find("void DeviceTree::collapseAllNodes")
    ]
    require("expandNodeRecursively" not in filter_body and
            "expandNodeRecursively" not in expand_body,
            "global filtering and expand-all must not recursively fetch children")
    snapshot_render = gui_source[
        gui_source.find("bool DeviceTree::loadDeviceTreeSnapshot"):
        gui_source.find("void DeviceTree::loadDeviceTree()")
    ]
    require("fetchDeviceAttributes" not in snapshot_render and
            "fetchChildDevices" not in snapshot_render,
            "snapshot rendering must not issue per-device IPC reads")
    require('"device_events"' in daemon_source,
            "device event history API must remain available")
    require("treeWidget->setMinimumWidth(640)" not in gui_source and
            "setMinimumWidth(660)" not in gui_source,
            "device tree must remain horizontally shrinkable")

    gui_device_source = read_text(gui_device_page)
    require("new PolicyEditorWidget(module, policies" in gui_device_source,
            "device module must reuse the standard policy editor")
    require("new DeviceTree" in gui_device_source and
            "new DeviceAttributeList" in gui_device_source and
            "new DeviceEventList" in gui_device_source,
            "device page must own the device tree, attributes and events")
    require("setColumnMinimumWidth(0, 660)" not in gui_device_source,
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
