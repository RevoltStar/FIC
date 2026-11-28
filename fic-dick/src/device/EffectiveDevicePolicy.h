#ifndef FIC_DEVICE_EFFECTIVE_DEVICE_POLICY_H
#define FIC_DEVICE_EFFECTIVE_DEVICE_POLICY_H

#include <fic/device-db/DB.h>
#include <fic/device-db/DeviceCategoryPolicy.h>

#include <optional>
#include <string>
#include <vector>

namespace fic::device_control {

// The effective rule of one device occurrence.
//
// Priority (unchanged): category DENY in `all` mode, explicit identity rule,
// explicit placement rule, category DENY in `new` mode, nearest explicit
// ancestor children_control, global default allow.
struct EffectivePolicy {
    std::string level = "allowed";
    std::string source = "default";
    int sourceDeviceId = -1;
    std::string reason;
};

// A rule value that is being evaluated BEFORE it is persisted. Only the
// addressed device occurrence is overridden; identity evaluation observes the
// override through the recorded rule value.
struct ControlOverride {
    int deviceId = -1;
    std::string controlLevel;
    bool controlExplicit = false;
    bool ignoreHierarchy = false;
    std::string childrenControl = "inherit";
};

DeviceInfo with_control_override(DeviceInfo device,
                                 const std::optional<ControlOverride>& override);

std::vector<DeviceInfo> device_path_to_root(
    DB& db,
    DeviceInfo device,
    const std::optional<ControlOverride>& override = std::nullopt);

// `liveAttributes` allows the caller to evaluate a device with udev attributes
// that are not (yet) stored in the database.
EffectivePolicy effective_device_policy(
    DB& db,
    DeviceInfo device,
    const std::optional<ControlOverride>& override = std::nullopt,
    const std::optional<DeviceIdentityTerms>& liveAttributes = std::nullopt);

// cpu / board / memory are the static (non-udev) hardware subsystems.
bool is_static_hardware_subsystem(const std::string& subsystem);

// The managed dynamic (udev-controlled) hardware subsystems. Virtual containers
// (`__virtual__`, `__udev__`, `__pci__`, ...) and other intermediate tree nodes
// are deliberately NOT hardware: they carry hierarchy only and must never be
// treated as a connected device on their own.
bool is_dynamic_hardware_subsystem(const std::string& subsystem);

} // namespace fic::device_control

#endif // FIC_DEVICE_EFFECTIVE_DEVICE_POLICY_H
