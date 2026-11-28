#include "device/EffectiveDevicePolicy.h"

#include <set>

namespace fic::device_control {

DeviceInfo with_control_override(DeviceInfo device,
                                 const std::optional<ControlOverride>& override) {
    if (override.has_value() && device.id == override->deviceId) {
        device.control_level = override->controlLevel;
        device.control_explicit = override->controlExplicit;
        device.ignore_hierarchy = override->ignoreHierarchy;
        device.children_control = override->childrenControl;
    }
    return device;
}

std::vector<DeviceInfo> device_path_to_root(
    DB& db,
    DeviceInfo device,
    const std::optional<ControlOverride>& override) {
    std::vector<DeviceInfo> path;
    std::set<int> seen;

    device = with_control_override(device, override);
    while (device.id > 0 && seen.insert(device.id).second) {
        path.push_back(device);
        if (device.parent_id <= 0) {
            break;
        }
        device = with_control_override(db.getDeviceById(device.parent_id), override);
        if (device.id == -1) {
            break;
        }
    }

    return path;
}

EffectivePolicy effective_device_policy(
    DB& db,
    DeviceInfo device,
    const std::optional<ControlOverride>& override,
    const std::optional<DeviceIdentityTerms>& liveAttributes) {
    device = with_control_override(device, override);
    const auto categories = db.getDeviceCategoryPolicyState();
    const auto attributes =
        liveAttributes ? *liveAttributes : db.getDeviceAttributes(device.id);
    const auto category = [&](bool hardOnly) -> std::optional<EffectivePolicy> {
        const auto denial = categoryDenial(categories, device, attributes, hardOnly);
        if (!denial) return std::nullopt;
        return EffectivePolicy{
            "blocked", "dc:" + denial->category + ":" + denial->mode, device.id,
            denial->mode == "all" ? "absolute category all DENY"
                                  : "identity absent from category epoch"};
    };
    if (const auto hard = category(true)) return *hard;

    const std::vector<DeviceInfo> path =
        device_path_to_root(db, device, override);

    for (DeviceInfo candidate :
         db.getDevicesByHashAndSubsystem(device.device_hash, device.subsystem)) {
        candidate = with_control_override(candidate, override);
        if (candidate.control_explicit && candidate.ignore_hierarchy) {
            return EffectivePolicy{
                candidate.control_level,
                "identity:" + std::to_string(candidate.id),
                candidate.id,
                "explicit same-identity rule with ignore_hierarchy=true"};
        }
    }

    if (device.control_explicit) {
        return EffectivePolicy{device.control_level,
                               "placement:" + std::to_string(device.id),
                               device.id,
                               "explicit placement rule"};
    }

    if (std::optional<EffectivePolicy> categoryPolicy = category(false)) {
        return categoryPolicy.value();
    }

    for (std::size_t index = 1; index < path.size(); ++index) {
        const DeviceInfo& parent = path[index];
        if (parent.children_control != "inherit") {
            return EffectivePolicy{
                parent.children_control == "deny" ? "blocked" : "allowed",
                "children:" + std::to_string(parent.id),
                parent.id,
                "nearest explicit ancestor children rule"};
        }
    }

    return EffectivePolicy{"allowed", "default", -1, "default allow"};
}

bool is_static_hardware_subsystem(const std::string& subsystem) {
    return subsystem == "cpu" || subsystem == "board" || subsystem == "memory";
}

} // namespace fic::device_control
