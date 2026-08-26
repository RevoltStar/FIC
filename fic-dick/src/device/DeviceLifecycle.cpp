#include "DeviceLifecycle.h"

#include <algorithm>
#include <set>

namespace fic::device_control {
namespace {

bool collectCurrentSubtree(DB& db,
                           int deviceId,
                           const std::string& bootId,
                           std::set<int>& seen,
                           std::vector<int>& ids,
                           std::string& error)
{
    if (!seen.insert(deviceId).second) {
        error = "cycle detected in current device subtree";
        return false;
    }

    const DeviceInfo device = db.getDeviceById(deviceId);
    if (device.id <= 0) {
        error = "device disappeared while collecting current subtree";
        return false;
    }
    if (device.boot_id != bootId) {
        return true;
    }

    ids.push_back(device.id);
    for (const DeviceInfo& child : db.getChildDevices(device.id)) {
        if (child.boot_id == bootId &&
            !collectCurrentSubtree(db, child.id, bootId, seen, ids, error)) {
            return false;
        }
    }
    return true;
}

bool hasCurrentBootChild(DB& db, int deviceId, const std::string& bootId)
{
    const std::vector<DeviceInfo> children = db.getChildDevices(deviceId);
    return std::any_of(children.begin(), children.end(), [&](const DeviceInfo& child) {
        return child.boot_id == bootId;
    });
}

} // namespace

DeviceLifecycle::DeviceLifecycle(DB& db)
    : db_(db)
{
}

bool DeviceLifecycle::recordDenyResult(int deviceId,
                                       bool enforced,
                                       const std::string& details,
                                       std::string& error)
{
    error.clear();
    if (deviceId <= 0) {
        error = "invalid device ID for deny result";
        return false;
    }
    if (db_.addDeviceEvent(DeviceEvent{
            0,
            deviceId,
            "block",
            enforced ? "success" : "error",
            details,
            ""
        }) <= 0) {
        error = "failed to record deny enforcement result";
        return false;
    }
    return true;
}

DeviceRemovalResult DeviceLifecycle::removeCurrentOccurrence(
    const std::string& devpath,
    const std::string& subsystem,
    const std::string& bootId)
{
    DeviceRemovalResult result;
    if (devpath.empty() || subsystem.empty() || bootId.empty()) {
        result.error = "devpath, subsystem and current boot_id are required";
        return result;
    }
    if (!db_.beginTransaction()) {
        result.error = "failed to begin device removal transaction";
        return result;
    }

    const DeviceInfo current =
        db_.getDeviceByDevpathSubsystemAndBootId(devpath, subsystem, bootId);
    if (current.id <= 0) {
        result.ok = true;
        result.alreadyRemoved = true;
    } else {
        result = disconnectCurrentSubtreeInTransaction(
            current.id, bootId, "device removed");
    }

    if (!result.ok) {
        db_.rollbackTransaction();
        result.affectedIds.clear();
        return result;
    }
    if (!db_.commitTransaction()) {
        result.ok = false;
        result.alreadyRemoved = false;
        result.error = "failed to commit device removal transaction";
        db_.rollbackTransaction();
        result.affectedIds.clear();
    }
    return result;
}

DeviceRemovalResult DeviceLifecycle::disconnectCurrentSubtree(
    int deviceId,
    const std::string& bootId,
    const std::string& eventDetails)
{
    DeviceRemovalResult result;
    result.deviceId = deviceId;
    if (deviceId <= 0 || bootId.empty()) {
        result.error = "valid device ID and current boot_id are required";
        return result;
    }
    if (!db_.beginTransaction()) {
        result.error = "failed to begin device removal transaction";
        return result;
    }

    result = disconnectCurrentSubtreeInTransaction(deviceId, bootId, eventDetails);
    if (!result.ok) {
        db_.rollbackTransaction();
        result.affectedIds.clear();
        return result;
    }
    if (!db_.commitTransaction()) {
        result.ok = false;
        result.alreadyRemoved = false;
        result.error = "failed to commit device removal transaction";
        db_.rollbackTransaction();
        result.affectedIds.clear();
    }
    return result;
}

DeviceRemovalResult DeviceLifecycle::disconnectCurrentSubtreeInTransaction(
    int deviceId,
    const std::string& bootId,
    const std::string& eventDetails)
{
    DeviceRemovalResult result;
    result.deviceId = deviceId;

    const DeviceInfo target = db_.getDeviceById(deviceId);
    if (target.id <= 0) {
        result.error = "device not found";
        return result;
    }
    if (target.boot_id != bootId) {
        result.ok = true;
        result.alreadyRemoved = true;
        return result;
    }

    std::set<int> seen;
    if (!collectCurrentSubtree(
            db_, target.id, bootId, seen, result.affectedIds, result.error)) {
        return result;
    }
    if (result.affectedIds.empty()) {
        result.ok = true;
        result.alreadyRemoved = true;
        return result;
    }

    for (auto it = result.affectedIds.rbegin(); it != result.affectedIds.rend(); ++it) {
        if (!db_.updateBootId(*it, "")) {
            result.error = "failed to clear current boot_id for device " +
                std::to_string(*it);
            return result;
        }
    }

    DeviceInfo parent = db_.getDeviceById(target.parent_id);
    while (parent.id > 0 && parent.subsystem == "__virtual__" &&
           parent.boot_id == bootId &&
           !hasCurrentBootChild(db_, parent.id, bootId)) {
        if (!db_.updateBootId(parent.id, "")) {
            result.error = "failed to clear empty virtual parent " +
                std::to_string(parent.id);
            return result;
        }
        parent = db_.getDeviceById(parent.parent_id);
    }

    if (db_.addDeviceEvent(DeviceEvent{
            0, target.id, "disconnect", "success", eventDetails, ""
        }) <= 0) {
        result.error = "failed to record device disconnect event";
        return result;
    }

    result.ok = true;
    return result;
}

} // namespace fic::device_control
