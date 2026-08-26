#include "device/DeviceLifecycle.h"

#include <fic/core/runtime/FicRuntimePaths.h>
#include <fic/device-db/DB.h>

#include <algorithm>
#include <cassert>
#include <filesystem>
#include <string>
#include <unistd.h>

namespace {

DeviceInfo addDevice(DB& db,
                     int parentId,
                     const std::string& hash,
                     const std::string& devpath,
                     const std::string& subsystem,
                     const std::string& bootId,
                     const std::string& controlLevel = "allowed")
{
    DeviceInfo device;
    device.device_hash = hash;
    device.devpath = devpath;
    device.subsystem = subsystem;
    device.device_type = subsystem;
    device.parent_id = parentId;
    device.control_level = controlLevel;
    device.control_explicit = controlLevel != "allowed";
    device.ignore_hierarchy = false;
    device.boot_id = bootId;
    device.notes = "device lifecycle test";
    device.children_control = "inherit";
    device.id = db.addDevice(device);
    assert(device.id > 0);
    return device;
}

bool containsId(const std::vector<int>& ids, int id)
{
    return std::find(ids.begin(), ids.end(), id) != ids.end();
}

void expectDisconnectEvent(DB& db, int deviceId)
{
    const std::vector<DeviceEvent> events = db.getDeviceEvents(deviceId, 20);
    assert(std::any_of(events.begin(), events.end(), [](const DeviceEvent& event) {
        return event.event_type == "disconnect" && event.event_result == "success";
    }));
}

} // namespace

int main()
{
    namespace fs = std::filesystem;
    using fic::device_control::DeviceLifecycle;
    using fic::device_control::DeviceRemovalResult;

    const std::string bootA = "BOOT_A";
    const std::string bootB = "BOOT_B";
    const fs::path root = fs::temp_directory_path() /
        ("fic-device-lifecycle-test-" + std::to_string(::getpid()));
    fs::remove_all(root);
    fs::create_directories(root / "log");
    fs::create_directories(root / "data");

    auto paths = fic::core::FicProductPaths::production();
    paths.privateBinDir = root / "bin";
    paths.configDir = root / "config";
    paths.languageDir = root / "lang";
    paths.logDir = root / "log";
    paths.notifyDir = root / "notify";
    paths.dataDir = root / "data";
    paths.shareDir = root / "share";
    paths.imageDir = root / "image";
    paths.runtimeDir = root / "run";
    paths.lockStatusFile = root / "lockstatus";
    paths.commandHashFile = root / "data/commandhash.txt";
    paths.deviceDatabaseFile = root / "data/devices.db";
    paths.deviceDatabaseLockFile = root / "log/devices.lock";
    paths.lockDebugLogFile = root / "log/db-lock.log";
    std::string error;
    assert(paths.validate(error));
    assert(fic::core::FicRuntimePaths::initialize(paths, error));

    DB db({
        paths.deviceDatabaseFile,
        paths.deviceDatabaseLockFile,
        paths.lockDebugLogFile,
        false
    });
    assert(db.initializeDatabase());
    const DeviceInfo devicesRoot = db.getDeviceByPath("/devices");
    assert(devicesRoot.id > 0);
    DeviceLifecycle lifecycle(db);

    // Successful DENY records the block but does not change presence.
    const DeviceInfo denied = addDevice(
        db, devicesRoot.id, "denied", "/devices/denied", "usb", bootB, "blocked");
    assert(lifecycle.recordDenyResult(
        denied.id, true, "authorized=0; source=placement", error));
    const DeviceInfo deniedAfter = db.getDeviceById(denied.id);
    assert(deniedAfter.boot_id == bootB);
    assert(deniedAfter.control_level == "blocked");
    const std::vector<DeviceEvent> denyEvents = db.getDeviceEvents(denied.id, 10);
    assert(!denyEvents.empty());
    assert(denyEvents.front().event_type == "block");
    assert(denyEvents.front().event_result == "success");

    // DENY -> child remove -> parent remove.
    const DeviceInfo parent1 = addDevice(
        db, devicesRoot.id, "parent1", "/devices/parent1", "usb", bootB, "blocked");
    const DeviceInfo child1 = addDevice(
        db, parent1.id, "child1", "/devices/parent1/child1", "usbmisc", bootB);
    DeviceRemovalResult removal = lifecycle.removeCurrentOccurrence(
        child1.devpath, child1.subsystem, bootB);
    assert(removal.ok && !removal.alreadyRemoved);
    assert(removal.deviceId == child1.id);
    assert(removal.affectedIds == std::vector<int>{child1.id});
    expectDisconnectEvent(db, child1.id);
    removal = lifecycle.removeCurrentOccurrence(parent1.devpath, parent1.subsystem, bootB);
    assert(removal.ok && !removal.alreadyRemoved);
    assert(removal.deviceId == parent1.id);
    assert(removal.affectedIds == std::vector<int>{parent1.id});
    assert(db.getDeviceById(parent1.id).boot_id.empty());
    assert(db.getDeviceById(child1.id).boot_id.empty());
    expectDisconnectEvent(db, parent1.id);

    // DENY -> parent remove -> child remove: child remove is an idempotent no-op.
    const DeviceInfo parent2 = addDevice(
        db, devicesRoot.id, "parent2", "/devices/parent2", "usb", bootB, "blocked");
    const DeviceInfo child2 = addDevice(
        db, parent2.id, "child2", "/devices/parent2/child2", "usbmisc", bootB);
    removal = lifecycle.removeCurrentOccurrence(parent2.devpath, parent2.subsystem, bootB);
    assert(removal.ok && !removal.alreadyRemoved);
    assert(containsId(removal.affectedIds, parent2.id));
    assert(containsId(removal.affectedIds, child2.id));
    const std::size_t rowsBeforeDuplicate = db.getAllDevices().size();
    const std::size_t childEventsBeforeDuplicate = db.getDeviceEvents(child2.id, 100).size();
    removal = lifecycle.removeCurrentOccurrence(child2.devpath, child2.subsystem, bootB);
    assert(removal.ok && removal.alreadyRemoved);
    assert(removal.affectedIds.empty());
    assert(db.getAllDevices().size() == rowsBeforeDuplicate);
    assert(db.getDeviceEvents(child2.id, 100).size() == childEventsBeforeDuplicate);

    // Duplicate remove neither mutates rows nor historical state.
    const DeviceInfo duplicate = addDevice(
        db, devicesRoot.id, "duplicate", "/devices/duplicate", "pci", bootB);
    removal = lifecycle.removeCurrentOccurrence(
        duplicate.devpath, duplicate.subsystem, bootB);
    assert(removal.ok && !removal.alreadyRemoved);
    const std::size_t rowsAfterFirstRemove = db.getAllDevices().size();
    const std::size_t eventsAfterFirstRemove = db.getDeviceEvents(duplicate.id, 100).size();
    removal = lifecycle.removeCurrentOccurrence(
        duplicate.devpath, duplicate.subsystem, bootB);
    assert(removal.ok && removal.alreadyRemoved);
    assert(db.getAllDevices().size() == rowsAfterFirstRemove);
    assert(db.getDeviceEvents(duplicate.id, 100).size() == eventsAfterFirstRemove);

    // The same placement in different boots: only the current occurrence changes.
    const DeviceInfo historical = addDevice(
        db, devicesRoot.id, "history-a", "/devices/reused", "usb", bootA);
    const DeviceInfo current = addDevice(
        db, devicesRoot.id, "history-b", "/devices/reused", "usb", bootB);
    removal = lifecycle.removeCurrentOccurrence(current.devpath, current.subsystem, bootB);
    assert(removal.ok && removal.deviceId == current.id);
    assert(db.getDeviceById(historical.id).boot_id == bootA);
    assert(db.getDeviceById(current.id).boot_id.empty());
    assert(db.getDeviceEvents(historical.id, 100).empty());
    expectDisconnectEvent(db, current.id);

    // Missing remove in the same boot is repaired by reconciliation by ID.
    const DeviceInfo stale = addDevice(
        db, devicesRoot.id, "stale", "/devices/stale", "block", bootB);
    removal = lifecycle.disconnectCurrentSubtree(
        stale.id, bootB, "device absent during reconciliation");
    assert(removal.ok && !removal.alreadyRemoved);
    assert(db.getDeviceById(stale.id).boot_id.empty());
    expectDisconnectEvent(db, stale.id);

    // Reboot semantics need no cleanup: BOOT_A is not current in BOOT_B.
    const DeviceInfo rebootHistorical = addDevice(
        db, devicesRoot.id, "reboot-a", "/devices/reboot", "pci", bootA);
    assert(db.getDeviceByDevpathSubsystemAndBootId(
        rebootHistorical.devpath, rebootHistorical.subsystem, bootB).id == -1);
    removal = lifecycle.removeCurrentOccurrence(
        rebootHistorical.devpath, rebootHistorical.subsystem, bootB);
    assert(removal.ok && removal.alreadyRemoved);
    assert(db.getDeviceById(rebootHistorical.id).boot_id == bootA);

    // Empty virtual parents are cleared, never recreated by remove.
    const DeviceInfo virtualParent = addDevice(
        db, devicesRoot.id, "virtual", "/devices/virtual-parent", "__virtual__", bootB);
    const DeviceInfo virtualChild = addDevice(
        db, virtualParent.id, "virtual-child", "/devices/virtual-parent/device", "usb", bootB);
    const std::size_t rowsBeforeVirtualRemove = db.getAllDevices().size();
    removal = lifecycle.removeCurrentOccurrence(
        virtualChild.devpath, virtualChild.subsystem, bootB);
    assert(removal.ok && !removal.alreadyRemoved);
    assert(db.getDeviceById(virtualParent.id).boot_id.empty());
    assert(db.getAllDevices().size() == rowsBeforeVirtualRemove);

    fs::remove_all(root);
    return 0;
}
