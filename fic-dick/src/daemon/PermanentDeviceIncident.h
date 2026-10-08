#ifndef FIC_DICK_DAEMON_PERMANENT_DEVICE_INCIDENT_H
#define FIC_DICK_DAEMON_PERMANENT_DEVICE_INCIDENT_H

#include <cstddef>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json_fwd.hpp>

namespace fic::device_control {

// One missing permanent-device obligation, as established by the device
// daemon's own database and observed presence.
struct PermanentViolation {
    int deviceId = -1;
    int sourceDeviceId = -1;
    std::string devpath;
    std::string source;
};

// Builds the bounded detector-event request for the main fic daemon.
//
// TRUST BOUNDARY: the device daemon reports the FACT of a violation only. The
// request deliberately carries NO severity and NO response-mode authority:
// the main daemon resolves the reaction from its own configuration
// (DC/DeviceControl/permanent_device_missing_severity) and owns the
// IncidentController. A compromised or misconfigured device daemon must never
// be able to choose ISOLATE for the host.
//
// The payload is bounded: at most MAX_DEVICE_INCIDENT_IDS device ids are
// carried, and the list is truncated rather than dropped, so an oversized
// fleet can never exceed the IPC frame while the fact of the violation is
// still delivered.
inline constexpr std::size_t MAX_DEVICE_INCIDENT_IDS = 64U;

nlohmann::json permanent_device_incident_request(
    const std::vector<PermanentViolation>& violations);

// True when the request is a well-formed bounded detector event. Used by the
// sender before dispatch and by tests to pin the schema.
bool is_valid_permanent_device_incident_request(
    const nlohmann::json& request, std::string& error);

} // namespace fic::device_control

#endif // FIC_DICK_DAEMON_PERMANENT_DEVICE_INCIDENT_H