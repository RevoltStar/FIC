#ifndef FIC_DICK_DAEMON_DEVICE_INCIDENT_SENDER_H
#define FIC_DICK_DAEMON_DEVICE_INCIDENT_SENDER_H

#include "daemon/PermanentDeviceIncident.h"

#include <fic/ipc/DeviceIncidentProtocol.h>

#include <string>
#include <vector>

namespace fic::device_control {

// The outcome of ONE detector-event delivery attempt.
//
// TRUST BOUNDARY: the device daemon reports the FACT only. The main daemon
// resolves the reaction severity from its own configuration and owns the
// IncidentController, so a compromised or misconfigured device daemon can
// never choose the host's containment level.
struct DeviceIncidentDelivery {
    // True only when the main daemon ACKNOWLEDGED the event: it processed a
    // valid event and durably recorded the required severity, or intentionally
    // ignored it (OFF/NONE/DISABLE). A DEGRADED containment does NOT un-
    // acknowledge a durably persisted severity.
    bool delivered = false;
    bool escalated = false;
    bool ignored = false;
    std::string mode;
    std::string requestedSeverity;
    std::string effectiveSeverity;
    std::string runtime;
    std::string message;
};

// Builds, schema-validates, sends and STRICTLY validates the reply of one
// detector event. A malformed event is never sent, an unreachable main daemon
// is a delivery failure, and an inconsistent acknowledgement is never repaired.
DeviceIncidentDelivery deliver_device_incident(
    fic::ipc::DeviceIncidentKind kind,
    const std::vector<PermanentViolation>& violations);

} // namespace fic::device_control

#endif // FIC_DICK_DAEMON_DEVICE_INCIDENT_SENDER_H
