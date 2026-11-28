#ifndef FIC_DEVICE_RULE_CHANGE_H
#define FIC_DEVICE_RULE_CHANGE_H

#include "device/EffectiveDevicePolicy.h"

#include <fic/device-db/DB.h>

#include <string>
#include <vector>

namespace fic::device_control {

// The pre-flight assessment of one individual rule change.
//
// The rule change is evaluated against the CURRENT database state plus the
// proposed rule value, before anything is persisted. Only devices whose
// effective level actually changes INTO `blocked` are reported: an already
// blocked device never prevents a rule change, so a previously blocked device
// can always be repaired.
//
//   connected_dynamic_blockers
//     connected (current boot) udev devices that would become blocked. The
//     whole operation is rejected: a connected device must be detached first.
//   connected_static_blockers
//     present (current boot) cpu/board/memory devices that would become
//     blocked. The rule IS persisted and the fact is reported to the main
//     daemon, which owns the incident reaction; static hardware is never
//     deactivated by the device daemon.
struct DeviceRuleChangeAssessment {
    std::vector<DeviceInfo> connected_dynamic_blockers;
    std::vector<DeviceInfo> connected_static_blockers;

    bool rejected() const { return !connected_dynamic_blockers.empty(); }
};

// Devices whose effective rule can change when `target` is modified: the
// target itself, every descendant (nearest-ancestor inheritance) and every
// occurrence of the same identity (identity rules).
std::vector<DeviceInfo> affected_devices_for_override(DB& db,
                                                      const DeviceInfo& target);

DeviceRuleChangeAssessment assess_device_rule_change(
    DB& db,
    const DeviceInfo& target,
    const ControlOverride& override,
    const std::string& bootId);

} // namespace fic::device_control

#endif // FIC_DEVICE_RULE_CHANGE_H
