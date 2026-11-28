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
    require("DC::reconcile" in fic_daemon_source and
            '"device_regenerate_policy"' in read_text(dc_policy),
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
    require('std::vector<std::string>{"all", "new"}' in dc_policy_source,
            "DC category policies must expose all/new select values")
    require(dc_policy_source.count("PossibleListPolicyTypeValue") == 4,
            "the category mode and the three detector severity settings must "
            "expose distinct select lists")
    require(
        dc_policy_source.count('{"STANDARD", "NONE", "SOFT", "HARD", "ISOLATE"}') == 2,
        "permanent-device-missing and block-failure severities must default to "
        "STANDARD with every severity token selectable")
    require(
        dc_policy_source.count('{"NONE", "SOFT", "STANDARD", "HARD", "ISOLATE"}') == 1,
        "forbidden static hardware severity must default to NONE with every "
        "severity token selectable")

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
        require(dc_config_values.get(f"{policy}.value") == "all",
                f"{policy} seed value must be all")
    for policy, factory in (
        ("permanent_device_missing_severity", "STANDARD"),
        ("static_device_present_severity", "NONE"),
        ("device_block_failed_severity", "STANDARD"),
    ):
        require(dc_config_values.get(f"{policy}.status") == "ENABLE",
                f"{policy} must be enabled by default")
        require(dc_config_values.get(f"{policy}.value") == factory,
                f"{policy} factory value must be {factory}")

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

    # A new failed block must MERGE into the pending delivery obligations and
    # never replace an undelivered one; an acknowledgement closes exactly the
    # obligations it carried.
    block_obligation = (root / "fic-dick" / "src" / "daemon" /
                        "BlockFailureObligation.h")
    block_obligation_source = read_text(block_obligation)
    for marker in ["remember(", "acknowledge(", "MAX_PENDING_BLOCK_FAILURES"]:
        require(marker in block_obligation_source,
                f"missing failed-block delivery obligation: {marker}")
    require("g_pendingBlockFailures = violations" not in daemon_source,
            "a new failed block must never replace the pending obligations")
    require("g_blockFailureObligations.remember(violations)" in daemon_source and
            "g_blockFailureObligations.acknowledge(attempted)" in daemon_source,
            "the failed-block obligations must be merged and acknowledged "
            "through the shared container")

    # Repeating an existing block transition must produce a new event: no
    # per-device "already reported" cache may suppress it.
    require("g_reportedStaticViolations" not in daemon_source,
            "static incident deduplication must stay with the IncidentController")
    require("pending_static_violations" not in daemon_source,
            "static violations must be reported as found, not cached")

    # A category DENY of a live device that has no database record yet is an
    # established violation and must be reported with its DEVPATH (never with a
    # synthetic id).
    category_marker = "bool enforce_connected_category_denials(DB& db, std::string& error) {"
    category_start = daemon_source.find(category_marker)
    category_body = daemon_source[category_start:category_start + 4000]
    require(category_start >= 0, "category enforcement must exist")
    require("if (live.id > 0) {" not in category_body,
            "a category failed block must be reported without a database record")
    require("dc:category" in category_body and
            "report_block_failed_violations" in category_body,
            "a category failed block must be reported")

    # The delayed connect/change handler relies on the existing udev enforcement
    # and reports an unconfirmed result; it must not re-run sysfs enforcement.
    require('"; attempt: "' not in event_handler and
            "enforcement attempt failed" not in event_handler,
            "the event handler must not retry sysfs enforcement")
    require("deny_enforcement_observed" in event_handler,
            "the event handler must verify the udev enforcement result")

    # Virtual tree nodes carry hierarchy only and must never be classified as
    # connected hardware.
    rule_change_source = read_text(
        root / "fic-dick" / "src" / "daemon" / "DeviceRuleChange.cpp")
    require("is_dynamic_hardware_subsystem(device.subsystem)" in rule_change_source,
            "a rule change must classify only real dynamic subsystems")
    require("} else {" not in rule_change_source,
            "a rule change must not treat virtual nodes as dynamic devices")

    # Collector trust: a successful tool exit is not usable data.
    collectors = root / "fic-dick" / "src" / "collectors"
    for name in ["CPUInfoCollector.cpp", "BoardInfoCollector.cpp",
                 "MemoryInfoCollector.cpp"]:
        require("inventoryProven_ = false" in read_text(collectors / name),
                f"{name} must mark an unusable inventory as unproven")
    for parser, header in [("parse_lscpu_output", "CPUInfoCollector.h"),
                           ("parse_dmidecode_output", "BoardInfoCollector.h"),
                           ("parse_dmidecode_modules", "MemoryInfoCollector.h")]:
        require(parser in read_text(collectors / header),
                f"missing static inventory parse contract: {parser}")
    require("MemoryModuleKind::Incomplete" in
            read_text(collectors / "MemoryInfoCollector.cpp"),
            "an unidentifiable memory module must make the inventory incomplete")

    # Proof lifecycle: type-strict reader, publication stamp, invalidation before
    # a new run and a failing exit when the result cannot be published.
    proof_source = read_text(
        root / "fic-dick" / "src" / "device" / "StaticInventoryProof.cpp")
    require("is_boolean()" in proof_source and "is_string()" in proof_source,
            "the proof reader must validate field types")
    require("published_at_ns" in proof_source,
            "the proof must carry a publication stamp")
    require("remove_static_inventory_proof" in proof_source,
            "the proof must be invalidatable")
    collector_main = read_text(root / "fic-dick" / "src" / "main.cpp")
    require(0 <= collector_main.find("remove_static_inventory_proof") <
                collector_main.find("CPUInfoCollector cic;"),
            "the previous proof must be invalidated BEFORE collecting")
    publish_body = collector_main[
        collector_main.find("write_static_inventory_proof"):
        collector_main.find("write_static_inventory_proof") + 900
    ]
    require("return 1;" in publish_body,
            "a failing inventory publication must fail the collector unit")
    watch_source = read_text(
        root / "fic-dick" / "src" / "daemon" / "StaticProofWatch.h")
    require("markProcessed" in watch_source and "pending" in watch_source,
            "the static proof watch must only close a fully processed "
            "publication")
    require("g_staticProofWatch.markProcessed(proofKey)" in daemon_source and
            "g_nextStaticProofRetry" in daemon_source,
            "a failed static check must be retried with a bounded interval")

    # Configuration migration: only completely absent NEW policies are added.
    schema_source = read_text(
        root / "fic-common" / "fic-core" / "src" / "config" /
        "ConfigSchemaManager.cpp")
    migration_start = schema_source.find(
        "bool ConfigSchemaManager::ensureDeviceIncidentSeverityDefaults(")
    require(migration_start >= 0, "the severity migration must exist")
    migration_body = schema_source[migration_start:migration_start + 3000]
    require("appendMissingDefaultGroups" in migration_body,
            "the severity migration must add whole policy groups only")
    require("permanent_device_missing_severity.status" not in migration_body,
            "the severity migration must not restore the permanent policy")

    return 0


if __name__ == "__main__":
    sys.exit(main())
