#ifndef FIC_DAEMON_DEVICE_INCIDENT_EVENT_H
#define FIC_DAEMON_DEVICE_INCIDENT_EVENT_H

#include <fic/core/incident/IncidentSeverity.h>

#include <fic/policy/Policy.h>

#include <string>

namespace fic::daemon {

// The authoritative detector reaction for a permanent-device-missing event,
// resolved from the trusted main-daemon configuration.
//
// The outcome is TYPED so the caller can never confuse the three very different
// meanings of "no severity": an INTENTIONAL disable (proven DISABLE or proven
// NONE) is a deliberate no-op, while an UNPROVEN configuration (missing policy,
// malformed status, invalid or missing value) is a security-critical state that
// must FAIL CLOSED to ISOLATE instead of silently suppressing the incident.
enum class DeviceMissingReactionKind {
    // Proven status=DISABLE: the administrator intentionally disabled the
    // detector reaction.
    Disabled,
    // Proven status=ENABLE with value=NONE: the administrator intentionally
    // configured no reaction.
    None,
    // Proven ENABLE with a valid raisable severity token.
    Severity,
    // Anything unprovable: missing policy, malformed status, invalid or
    // missing value. Fail closed.
    Unproven
};

struct DeviceMissingReaction {
    DeviceMissingReactionKind kind = DeviceMissingReactionKind::Unproven;
    ::fic::core::IncidentSeverity severity =
        ::fic::core::IncidentSeverity::Isolate;
    std::string diagnostic;
};

// Resolves the detector reaction from the SAME policy object the registry
// owns. This is the production function the incident handler calls; tests use
// it directly with a temporary module configuration.
DeviceMissingReaction resolve_device_missing_severity(Policy& policy);

// Builds the IPC acknowledgement the main daemon returns for a
// permanent-device-missing event. This is the PRODUCTION response builder the
// incident handler uses; the device daemon validates replies with
// parse_device_incident_acknowledgement(), so the two sides of the contract
// are testable against each other without a live IPC round-trip.
//
// Semantics (the authoritative ACK matrix):
//
//   intentional ignore (DISABLE / NONE / response mode OFF):
//     acknowledged=true, persistence_confirmed=false, ignored=true —
//     the delivery obligation is closed, and NO new persistence obligation
//     exists, so persistence_confirmed=false is NOT an error;
//   raise performed:
//     acknowledged = persistence_confirmed = the actual
//     IncidentResult::persistenceConfirmed, incident_ok = IncidentResult::ok
//     (independent of the containment outcome), ignored=ignoredByMode.
json make_device_incident_ack_response(
    const DeviceMissingReaction& reaction,
    bool ignoredByMode,
    bool persistenceConfirmed,
    bool incidentOk,
    const std::string& requestedSeverityToken,
    const std::string& effectiveSeverityToken,
    const std::string& responseModeToken,
    const std::string& runtimeToken,
    bool escalated,
    bool persistentStateBroken,
    const std::string& detail);

} // namespace fic::daemon

#endif // FIC_DAEMON_DEVICE_INCIDENT_EVENT_H