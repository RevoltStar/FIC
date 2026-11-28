// Regression tests for the pre-flight assessment of an individual device rule
// change.
//
// assess_device_rule_change() is the SINGLE production function all four
// mutation handlers (control level, children control, ignore_hierarchy, reset)
// call before touching the database, so these tests pin the accepted contract:
//
//   * a connected dynamic device that becomes effectively blocked rejects the
//     whole operation (nothing is persisted, no incident is created);
//   * a present static device that becomes effectively blocked is reported for
//     the main daemon (the rule itself is persisted);
//   * an already effective block never prevents a rule change, so a previously
//     blocked device can always be repaired;
//   * identity occurrences and descendants are part of the affected set.
#include "daemon/DeviceRuleChange.h"

#include <fic/core/runtime/FicRuntimePaths.h>
#include <fic/device-db/DB.h>

#include <cassert>
#include <filesystem>
#include <iostream>
#include <string>
#include <unistd.h>

namespace {

const std::string kBoot = "test-boot";
const std::string kOldBoot = "old-boot";

void require(bool condition, const std::string& message) {
    if (!condition) {
        std::cerr << "FAILED: " << message << "\n";
        std::exit(1);
    }
}

DeviceInfo addDevice(DB& db,
                     int parentId,
                     const std::string& hash,
                     const std::string& devpath,
                     const std::string& subsystem,
                     const std::string& bootId,
                     const std::string& controlLevel = "allowed",
                     bool controlExplicit = false,
                     bool ignoreHierarchy = false,
                     const std::string& childrenControl = "inherit") {
    DeviceInfo device;
    device.device_hash = hash;
    device.devpath = devpath;
    device.subsystem = subsystem;
    device.device_type = subsystem;
    device.parent_id = parentId;
    device.control_level = controlLevel;
    device.control_explicit = controlExplicit;
    device.ignore_hierarchy = ignoreHierarchy;
    device.children_control = childrenControl;
    device.boot_id = bootId;
    device.notes = "rule change test";
    device.id = db.addDevice(device);
    assert(device.id > 0);
    return device;
}

bool containsDevice(const std::vector<DeviceInfo>& devices, int deviceId) {
    for (const DeviceInfo& device : devices) {
        if (device.id == deviceId) return true;
    }
    return false;
}

std::vector<int> idsOf(const std::vector<DeviceInfo>& devices) {
    std::vector<int> ids;
    for (const DeviceInfo& device : devices) ids.push_back(device.id);
    return ids;
}

std::string describe(const std::vector<int>& ids) {
    std::string text;
    for (const int id : ids) text += " " + std::to_string(id);
    return text;
}

} // namespace

int main() {
    namespace fs = std::filesystem;
    using namespace fic::device_control;

    const fs::path root = fs::temp_directory_path() /
        ("fic-device-rule-change-test-" + std::to_string(::getpid()));
    fs::remove_all(root);
    fs::create_directories(root / "log");
    fs::create_directories(root / "data");

    auto productPaths = fic::core::FicProductPaths::production();
    productPaths.privateBinDir = root / "bin";
    productPaths.configDir = root / "config";
    productPaths.languageDir = root / "lang";
    productPaths.logDir = root / "log";
    productPaths.notifyDir = root / "notify";
    productPaths.dataDir = root / "data";
    productPaths.shareDir = root / "share";
    productPaths.imageDir = root / "image";
    productPaths.runtimeDir = root / "run";
    productPaths.lockStatusFile = root / "lockstatus";
    productPaths.commandHashFile = root / "data/commandhash.txt";
    productPaths.deviceDatabaseFile = root / "data/devices.db";
    productPaths.deviceDatabaseLockFile = root / "log/devices.lock";
    productPaths.lockDebugLogFile = root / "log/db-lock.log";
    std::string error;
    require(productPaths.validate(error), error);
    require(fic::core::FicRuntimePaths::initialize(productPaths, error), error);

    DB db({
        productPaths.deviceDatabaseFile,
        productPaths.deviceDatabaseLockFile,
        productPaths.lockDebugLogFile,
        false
    });
    require(db.initializeDatabase(), "database must initialize");

    const DeviceInfo computerRoot = db.getComputerRoot();
    require(computerRoot.id > 0, "computer root must exist");
    const int devicesContainerId = db.getVirtualContainerId("devices");
    require(devicesContainerId > 0, "devices container must exist");
    const DeviceInfo cpuContainer = db.getDeviceByPath("/cpu_list");
    const DeviceInfo memoryContainer = db.getDeviceByPath("/memory_list");
    require(cpuContainer.id > 0 && memoryContainer.id > 0,
            "static containers must exist");

    const DeviceInfo pciHost = addDevice(
        db, devicesContainerId, "pci-host", "/devices/pci0000:00",
        "pci", kBoot);
    const DeviceInfo hub = addDevice(
        db, pciHost.id, "usb-hub", "/devices/pci0000:00/usb1", "usb", kBoot);
    const DeviceInfo connectedChild = addDevice(
        db, hub.id, "usb-child", "/devices/pci0000:00/usb1/1-1", "usb", kBoot);
    const DeviceInfo explicitChild = addDevice(
        db, hub.id, "usb-explicit", "/devices/pci0000:00/usb1/1-2",
        "usb", kBoot, "allowed", true);
    const DeviceInfo detachedChild = addDevice(
        db, hub.id, "usb-detached", "/devices/pci0000:00/usb1/1-3", "usb",
        kOldBoot);
    const DeviceInfo blockedChild = addDevice(
        db, hub.id, "usb-blocked", "/devices/pci0000:00/usb1/1-4", "usb",
        kBoot, "blocked", true);
    const DeviceInfo presentCpu = addDevice(
        db, cpuContainer.id, "cpu-0", "/cpu_list/cpu-0", "cpu", kBoot);
    const DeviceInfo presentMemory = addDevice(
        db, memoryContainer.id, "memory-0", "/memory_list/memory-0",
        "memory", kBoot);

    // R1: blocking a connected dynamic device is rejected.
    {
        const ControlOverride override{
            connectedChild.id, "blocked", true, false, "inherit"};
        const DeviceRuleChangeAssessment assessment = assess_device_rule_change(
            db, connectedChild, override, kBoot);
        require(assessment.rejected(),
                "blocking a connected dynamic device must be rejected");
        require(containsDevice(
                    assessment.connected_dynamic_blockers, connectedChild.id),
                "the connected child must be reported as a blocker");
        require(assessment.connected_static_blockers.empty(),
                "a dynamic blocker must not be reported as static hardware");
    }

    // R2: blocking a detached dynamic device is accepted.
    {
        const ControlOverride override{
            detachedChild.id, "blocked", true, false, "inherit"};
        const DeviceRuleChangeAssessment assessment = assess_device_rule_change(
            db, detachedChild, override, kBoot);
        require(!assessment.rejected(),
                "blocking a detached dynamic device must be accepted");
    }

    // R3: denying the children of a connected hub is rejected while a
    // connected child would become blocked.
    {
        ControlOverride override{
            hub.id, hub.control_level, hub.control_explicit,
            hub.ignore_hierarchy, "deny"};
        const DeviceRuleChangeAssessment assessment = assess_device_rule_change(
            db, hub, override, kBoot);
        require(assessment.rejected(),
                "children deny must be rejected for a connected child");
        require(containsDevice(
                    assessment.connected_dynamic_blockers, connectedChild.id),
                "the inheriting connected child must be a blocker");

        // R4: an explicit allow that overrides the inherited deny keeps the
        // operation acceptable.
        require(db.updateDeviceControl(
                    explicitChild.id, "allowed", true, false, "inherit"),
                "explicit allow must be stored");
        require(db.updateDeviceControl(
                    connectedChild.id, "allowed", true, false, "inherit"),
                "explicit allow must be stored");
        const DeviceInfo hubAfter = db.getDeviceById(hub.id);
        require(!assess_device_rule_change(
                     db, hubAfter,
                     ControlOverride{hubAfter.id, hubAfter.control_level,
                                     hubAfter.control_explicit,
                                     hubAfter.ignore_hierarchy, "deny"},
                     kBoot)
                     .rejected(),
                "explicit child rules must override the inherited deny");
        // Restore the child to inheritance so later cases see the raw tree.
        require(db.updateDeviceControl(connectedChild.id, "allowed", false,
                                       false, "inherit"),
                "reset must be stored");
    }

    // R5: an already blocked connected device never prevents a change that
    // makes it allowed again (repair path).
    {
        const ControlOverride override{blockedChild.id, "allowed", true, false,
                                       "inherit"};
        require(!assess_device_rule_change(db, blockedChild, override, kBoot)
                     .rejected(),
                "a rule that only removes a block must be accepted");
        const ControlOverride noChange{blockedChild.id, "blocked", true, false,
                                       "inherit"};
        require(!assess_device_rule_change(db, blockedChild, noChange, kBoot)
                     .rejected(),
                "a rule that does not create a new block must be accepted");
    }

    // R6: ignore_hierarchy can turn the identity rule on for another connected
    // occurrence, which is a new restriction of that connected device.
    {
        const DeviceInfo identityA = addDevice(
            db, hub.id, "identity-a", "/devices/pci0000:00/usb1/1-5", "usb",
            kBoot, "blocked", true, false);
        const DeviceInfo identityB = addDevice(
            db, hub.id, "identity-a", "/devices/pci0000:00/usb1/1-6", "usb",
            kBoot);
        const DeviceRuleChangeAssessment assessment = assess_device_rule_change(
            db, identityA,
            ControlOverride{identityA.id, "blocked", true, true, "inherit"},
            kBoot);
        require(assessment.rejected(),
                "an identity rule that blocks another connected occurrence "
                "must be rejected");
        require(containsDevice(
                    assessment.connected_dynamic_blockers, identityB.id),
                "the other occurrence must be reported as a blocker");
        // The same change with both occurrences already blocked is accepted.
        require(db.updateDeviceControl(identityB.id, "blocked", true, false,
                                       "inherit"),
                "existing block must be stored");
        const DeviceInfo identityBBlocked = db.getDeviceById(identityB.id);
        require(!assess_device_rule_change(
                     db, identityA,
                     ControlOverride{identityA.id, "blocked", true, true,
                                     "inherit"},
                     kBoot)
                     .rejected(),
                "already blocked occurrences must not block the change");
        require(!assess_device_rule_change(
                     db, identityBBlocked,
                     ControlOverride{identityBBlocked.id, "blocked", true, true,
                                     "inherit"},
                     kBoot)
                     .rejected(),
                "an idempotent ignore_hierarchy change must be accepted");
    }

    // R7: resetting to inheritance can reveal an ancestor deny.
    {
        const DeviceInfo denyHost = addDevice(
            db, pciHost.id, "deny-host", "/devices/pci0000:00/usb2", "usb",
            kBoot, "allowed", false, false, "deny");
        const DeviceInfo rescued = addDevice(
            db, denyHost.id, "rescued", "/devices/pci0000:00/usb2/2-1", "usb",
            kBoot, "allowed", true);
        const DeviceRuleChangeAssessment rejectedReset =
            assess_device_rule_change(
                db, rescued, ControlOverride{rescued.id, "allowed", false, false,
                                             "inherit"},
                kBoot);
        require(rejectedReset.rejected(),
                "a reset that reveals an inherited deny must be rejected");
        // Mark the device blocked first: the same reset stays acceptable
        // because it cannot create a NEW block.
        require(db.updateDeviceControl(rescued.id, "blocked", true, false,
                                       "inherit"),
                "blocked rule must be stored");
        const DeviceInfo rescuedBlocked = db.getDeviceById(rescued.id);
        require(!assess_device_rule_change(
                     db, rescuedBlocked,
                     ControlOverride{rescuedBlocked.id, "blocked", false, false,
                                     "inherit"},
                     kBoot)
                     .rejected(),
                "reset of an already blocked device must be accepted");
    }

    // R8: blocking static hardware is not a dynamic blocker: the rule is
    // persisted and the fact is reported separately.
    {
        const DeviceRuleChangeAssessment cpuAssessment =
            assess_device_rule_change(
                db, presentCpu,
                ControlOverride{presentCpu.id, "blocked", true, false,
                                "inherit"},
                kBoot);
        require(!cpuAssessment.rejected(),
                "blocking a present CPU must not be rejected");
        require(containsDevice(cpuAssessment.connected_static_blockers,
                               presentCpu.id),
                "the present CPU must be reported as a static violation");

        const DeviceInfo cpuContainerNow = db.getDeviceById(cpuContainer.id);
        const DeviceRuleChangeAssessment containerAssessment =
            assess_device_rule_change(
                db, cpuContainerNow,
                ControlOverride{cpuContainer.id, "allowed", true, false, "deny"},
                kBoot);
        require(!containerAssessment.rejected(),
                "a static container children deny must not be rejected");
        require(containsDevice(containerAssessment.connected_static_blockers,
                               presentCpu.id),
                "the CPU under the container must be a static violation");

        const DeviceInfo memoryContainerNow =
            db.getDeviceById(memoryContainer.id);
        const DeviceRuleChangeAssessment memoryAssessment =
            assess_device_rule_change(
                db, memoryContainerNow,
                ControlOverride{memoryContainer.id, "allowed", true, false,
                                "deny"},
                kBoot);
        require(containsDevice(memoryAssessment.connected_static_blockers,
                               presentMemory.id),
                "the installed memory must be a static violation");
    }

    // R9: a mixed change that restricts both a connected dynamic device and
    // static hardware is rejected as a whole, and the static list is still
    // available for diagnostics.
    {
        const DeviceInfo computerRootNow = db.getDeviceById(computerRoot.id);
        const DeviceRuleChangeAssessment assessment = assess_device_rule_change(
            db, computerRootNow,
            ControlOverride{computerRoot.id, "allowed", true, false, "deny"},
            kBoot);
        require(assessment.rejected(),
                "a mixed change must be rejected by the dynamic blocker");
        require(!assessment.connected_dynamic_blockers.empty() &&
                    !assessment.connected_static_blockers.empty(),
                "the mixed change must report both dynamic and static devices: "
                "dynamic=[" +
                    describe(idsOf(assessment.connected_dynamic_blockers)) +
                    "] static=[" +
                    describe(idsOf(assessment.connected_static_blockers)) + "]");
    }

    // R10: an unproven boot id never classifies a device as connected.
    {
        const DeviceRuleChangeAssessment assessment = assess_device_rule_change(
            db, connectedChild,
            ControlOverride{connectedChild.id, "blocked", true, false,
                            "inherit"},
            "");
        require(!assessment.rejected() &&
                    assessment.connected_dynamic_blockers.empty() &&
                    assessment.connected_static_blockers.empty(),
                "an empty boot id must not produce violations");
    }

    // R11: the affected set covers the target, its subtree and the identity
    // occurrences only.
    {
        const std::vector<DeviceInfo> affected =
            affected_devices_for_override(db, hub);
        require(containsDevice(affected, hub.id),
                "the target must be affected");
        require(containsDevice(affected, connectedChild.id),
                "descendants must be affected");
        require(!containsDevice(affected, presentCpu.id),
                "unrelated devices must not be affected");
        require(affected.size() <= 8,
                "the affected set must stay bounded to the subtree and "
                "identity occurrences");
    }

    // R12: virtual tree nodes are NOT hardware.
    //
    // UDEVInfoCollector::create_virtual_device_config() stores intermediate
    // tree nodes with subsystem "__virtual__" and the CURRENT boot id, so a
    // present virtual node must never reject a rule change on its own. Its
    // influence on real descendants is preserved through their own effective
    // policy, which the same assessment evaluates.
    {
        const DeviceInfo virtualNode = addDevice(
            db, hub.id, "virtual_hash_for_device[/devices/pci0000:00/usb1/1-7]",
            "/devices/pci0000:00/usb1/1-7", "__virtual__", kBoot);
        const DeviceRuleChangeAssessment loneVirtual =
            assess_device_rule_change(
                db, virtualNode,
                ControlOverride{virtualNode.id, "blocked", true, false,
                                "inherit"},
                kBoot);
        require(!loneVirtual.rejected(),
                "a virtual node without a real descendant must not be rejected");
        require(loneVirtual.connected_dynamic_blockers.empty(),
                "a virtual node must not be reported as a dynamic blocker");

        // A real connected descendant that would inherit a denied container
        // still rejects the change and is the only reported blocker.
        const DeviceInfo realChildUnderVirtual = addDevice(
            db, virtualNode.id, "usb-real-under-virtual",
            "/devices/pci0000:00/usb1/1-7/1-7:1.0", "usb", kBoot);
        const DeviceRuleChangeAssessment withRealChild =
            assess_device_rule_change(
                db, virtualNode,
                ControlOverride{virtualNode.id, virtualNode.control_level,
                                virtualNode.control_explicit,
                                virtualNode.ignore_hierarchy, "deny"},
                kBoot);
        require(withRealChild.rejected(),
                "a real connected descendant of a virtual node must reject the "
                "change");
        require(containsDevice(withRealChild.connected_dynamic_blockers,
                              realChildUnderVirtual.id),
                "the real descendant must be reported as the blocker");
        require(!containsDevice(withRealChild.connected_dynamic_blockers,
                                virtualNode.id),
                "the virtual node itself must never be a blocker");

        // Every real connected descendant explicitly allowed: the change is
        // accepted.
        require(db.updateDeviceControl(realChildUnderVirtual.id, "allowed",
                                       true, false, "inherit"),
                "explicit allow must be stored");
        const DeviceInfo virtualNodeNow = db.getDeviceById(virtualNode.id);
        require(!assess_device_rule_change(
                     db, virtualNodeNow,
                     ControlOverride{virtualNode.id, virtualNode.control_level,
                                     virtualNode.control_explicit,
                                     virtualNode.ignore_hierarchy, "deny"},
                     kBoot)
                     .rejected(),
                "explicitly allowed real descendants must permit the change");
    }

    // R13: a static container change still reaches the real static devices.
    // `/board_list` is a hierarchy node; the installed board is the hardware.
    {
        const DeviceInfo boardContainer = db.getDeviceByPath("/board_list");
        require(boardContainer.id > 0, "board container must exist");
        const DeviceInfo presentBoard = addDevice(
            db, boardContainer.id, "board-0", "/board_list/board-0", "board",
            kBoot);
        const DeviceInfo boardContainerNow = db.getDeviceById(boardContainer.id);
        const DeviceRuleChangeAssessment assessment =
            assess_device_rule_change(
                db, boardContainerNow,
                ControlOverride{boardContainer.id, "allowed", true, false,
                                "deny"},
                kBoot);
        require(!assessment.rejected(),
                "a static container children deny must not be rejected");
        require(containsDevice(assessment.connected_static_blockers,
                               presentBoard.id),
                "the installed board must be a static violation");
        require(assessment.connected_static_blockers.size() == 1,
                "only real static hardware must be reported, not the container");
    }

    fs::remove_all(root);
    std::cout << "Device rule change pre-flight contract proven\n";
    return 0;
}
