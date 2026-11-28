#ifndef FIC_DICK_DAEMON_PERMANENT_DEVICE_INCIDENT_H
#define FIC_DICK_DAEMON_PERMANENT_DEVICE_INCIDENT_H

#include <cstddef>
#include <optional>
#include <string>
#include <vector>

#include <fic/ipc/DeviceIncidentProtocol.h>
#include <nlohmann/json_fwd.hpp>

namespace fic::device_control {

// One established device violation, as proven by the device daemon's own
// database and observed device presence.
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
// (DC/DeviceControl/<kind>_severity) and owns the IncidentController. A
// compromised or misconfigured device daemon must never be able to choose
// ISOLATE for the host.
//
// The payload is bounded: at most MAX_DEVICE_INCIDENT_IDS device ids are
// carried, and the list is truncated rather than dropped, so an oversized
// fleet can never exceed the IPC frame while the fact of the violation is
// still delivered.
inline constexpr std::size_t MAX_DEVICE_INCIDENT_IDS = 64U;

nlohmann::json device_incident_request(
    fic::ipc::DeviceIncidentKind kind,
    const std::vector<PermanentViolation>& violations);

// True when the request is a well-formed bounded detector event of the
// expected kind. Used by the sender before dispatch and by tests to pin the
// schema.
bool is_valid_device_incident_request(
    const nlohmann::json& request,
    fic::ipc::DeviceIncidentKind expectedKind,
    std::string& error);

// The acknowledgement the main daemon must return for a detector event.
//
// acknowledged and containment are deliberately SEPARATE: a durably persisted
// severity with a DEGRADED containment is STILL an acknowledged event, because
// the incident state owns the containment retry lifecycle; re-delivering it
// would only re-run actions that already failed.
struct DeviceIncidentAcknowledgement {
    bool valid = false;
    bool acknowledged = false;
    bool persistenceConfirmed = false;
    bool ignored = false;
    bool escalated = false;
    std::string mode;
    std::string requestedSeverity;
    std::string effectiveSeverity;
    std::string runtime;
    std::string message;
    std::string error;
};

// STRICT acknowledgement validation: the response must name THIS command, be
// well-typed, and carry a consistent acknowledged/persistence pair. A response
// from an old daemon, a wrong command, or a malformed shape is a delivery
// failure, never a success.
DeviceIncidentAcknowledgement parse_device_incident_acknowledgement(
    const nlohmann::json& response,
    fic::ipc::DeviceIncidentKind expectedKind);

} // namespace fic::device_control

#endif // FIC_DICK_DAEMON_PERMANENT_DEVICE_INCIDENT_H