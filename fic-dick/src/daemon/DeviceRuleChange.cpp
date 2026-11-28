#include "daemon/DeviceRuleChange.h"

#include <set>

namespace fic::device_control {

std::vector<DeviceInfo> affected_devices_for_override(DB& db,
                                                      const DeviceInfo& target) {
    std::vector<DeviceInfo> devices;
    std::set<int> seen;

    auto addDevice = [&](const DeviceInfo& device) {
        if (device.id > 0 && seen.insert(device.id).second) {
            devices.push_back(device);
        }
    };

    addDevice(target);
    // Nearest-ancestor children rules apply to the whole subtree.
    for (const DeviceInfo& child : db.getDescendantDevices(target.id)) {
        addDevice(child);
    }
    // An identity rule applies to every occurrence of the same identity, not
    // only to the addressed occurrence.
    for (const DeviceInfo& occurrence :
         db.getDevicesByHashAndSubsystem(target.device_hash, target.subsystem)) {
        addDevice(occurrence);
    }

    return devices;
}

DeviceRuleChangeAssessment assess_device_rule_change(
    DB& db,
    const DeviceInfo& target,
    const ControlOverride& override,
    const std::string& bootId) {
    DeviceRuleChangeAssessment assessment;
    if (bootId.empty()) {
        // Without the current boot id neither presence nor absence is proven,
        // so no device can be classified as connected. This mirrors the
        // existing permanent-device handling: an unproven inventory never
        // produces a violation.
        return assessment;
    }

    for (const DeviceInfo& device : affected_devices_for_override(db, target)) {
        if (device.boot_id != bootId) {
            continue;
        }
        const EffectivePolicy before = effective_device_policy(db, device);
        if (before.level == "blocked") {
            // An already effective block is not a new restriction.
            continue;
        }
        const EffectivePolicy after =
            effective_device_policy(db, device, override);
        if (after.level != "blocked") {
            continue;
        }
        if (is_static_hardware_subsystem(device.subsystem)) {
            assessment.connected_static_blockers.push_back(device);
        } else {
            assessment.connected_dynamic_blockers.push_back(device);
        }
    }

    return assessment;
}

} // namespace fic::device_control
