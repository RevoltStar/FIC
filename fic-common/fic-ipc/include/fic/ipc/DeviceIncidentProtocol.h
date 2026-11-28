#ifndef FIC_DEVICE_INCIDENT_PROTOCOL_H
#define FIC_DEVICE_INCIDENT_PROTOCOL_H

#include <string>

namespace fic::ipc {

// Shared detector-event contract between the privileged device daemon
// (fic-dick) and the main fic daemon.
//
// The device daemon establishes the FACT of a device violation and sends a
// bounded event naming only device ids. It never carries a severity or a
// response mode: the main daemon resolves the reaction from its OWN
// configuration and owns the IncidentController.
//
// Three independent violation kinds are supported. Each kind has its own
// command, its own severity policy and its own reason prefix, so an
// acknowledged event of one kind can never discharge an undelivered violation
// of another kind.
enum class DeviceIncidentKind {
    // A permanent obligation whose device is absent.
    PermanentDeviceMissing,
    // A present cpu/board/memory device whose effective rule is `blocked`.
    StaticDevicePresent,
    // A forbidden dynamic device that could not be restricted.
    DeviceBlockFailed
};

inline const char* deviceIncidentCommand(DeviceIncidentKind kind) {
    switch (kind) {
    case DeviceIncidentKind::StaticDevicePresent:
        return "incident_device_present";
    case DeviceIncidentKind::DeviceBlockFailed:
        return "incident_device_block_failed";
    case DeviceIncidentKind::PermanentDeviceMissing:
        break;
    }
    return "incident_device_missing";
}

inline bool deviceIncidentKindFromCommand(const std::string& command,
                                          DeviceIncidentKind& kind) {
    if (command == "incident_device_missing") {
        kind = DeviceIncidentKind::PermanentDeviceMissing;
        return true;
    }
    if (command == "incident_device_present") {
        kind = DeviceIncidentKind::StaticDevicePresent;
        return true;
    }
    if (command == "incident_device_block_failed") {
        kind = DeviceIncidentKind::DeviceBlockFailed;
        return true;
    }
    return false;
}

// The DC/DeviceControl policy that owns the reaction severity of this kind.
// These policies are detector settings, not udev configuration: applying them
// never regenerates udev rules and never requires the device daemon.
inline const char* deviceIncidentSeverityPolicy(DeviceIncidentKind kind) {
    switch (kind) {
    case DeviceIncidentKind::StaticDevicePresent:
        return "static_device_present_severity";
    case DeviceIncidentKind::DeviceBlockFailed:
        return "device_block_failed_severity";
    case DeviceIncidentKind::PermanentDeviceMissing:
        break;
    }
    return "permanent_device_missing_severity";
}

// Packaged factory severity token of each kind (see the DC.conf defaults).
inline const char* deviceIncidentFactorySeverity(DeviceIncidentKind kind) {
    switch (kind) {
    case DeviceIncidentKind::StaticDevicePresent:
        return "NONE";
    case DeviceIncidentKind::DeviceBlockFailed:
    case DeviceIncidentKind::PermanentDeviceMissing:
        break;
    }
    return "STANDARD";
}

// The incident reason prefix, so audit and log records of different kinds stay
// distinguishable.
inline const char* deviceIncidentReasonPrefix(DeviceIncidentKind kind) {
    switch (kind) {
    case DeviceIncidentKind::StaticDevicePresent:
        return "STATIC_DEVICE_PRESENT:";
    case DeviceIncidentKind::DeviceBlockFailed:
        return "DEVICE_BLOCK_FAILED:";
    case DeviceIncidentKind::PermanentDeviceMissing:
        break;
    }
    return "PERMANENT_DEVICE_MISSING:";
}

} // namespace fic::ipc

#endif // FIC_DEVICE_INCIDENT_PROTOCOL_H
