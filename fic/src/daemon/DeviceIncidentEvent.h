#ifndef FIC_DAEMON_DEVICE_INCIDENT_EVENT_H
#define FIC_DAEMON_DEVICE_INCIDENT_EVENT_H

#include <fic/core/incident/IncidentSeverity.h>
#include <fic/ipc/DeviceIncidentProtocol.h>

#include <fic/policy/Policy.h>

#include <optional>
#include <string>

namespace fic::daemon {

// The authoritative detector reaction for one device violation event, resolved
// from the trusted main-daemon configuration.
//
// The outcome is TYPED so the caller can never confuse the three very different
// meanings of "no severity": an INTENTIONAL disable (proven DISABLE or proven
// NONE) is a deliberate no-op, while an UNPROVEN configuration (malformed
// status, invalid or missing value) is a security-critical state that must FAIL
// CLOSED to ISOLATE instead of silently suppressing the incident.
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

// Which DC/DeviceControl policy owns the reaction and what the packaged
// factory default is.
//
// `factoryDefaultForAbsentPolicy` is the value used when the policy is
// COMPLETELY absent from the configuration file (neither .status nor .value).
// That happens when an existing installation is upgraded before the additive
// `ensure-config` step appended the new severity policy. Everything that is
// PRESENT but unprovable still fails closed; only a genuinely unconfigured
// policy falls back to the factory default, which is what a fresh installation
// would have.
struct DeviceIncidentSeveritySpec {
    std::string policyName;
    std::optional<std::string> factoryDefaultForAbsentPolicy;
};

// Resolves the detector reaction from the SAME policy object the registry
// owns. This is the production function the incident handler calls; tests use
// it directly with a temporary module configuration.
DeviceMissingReaction resolve_device_incident_severity(
    Policy& policy, const DeviceIncidentSeveritySpec& spec);

// The permanent-device-missing setting keeps its original fail-closed
// semantics (an absent entry is unproven, never a silent default).
DeviceMissingReaction resolve_device_missing_severity(Policy& policy);

// The spec of one incident kind: which policy owns it and which factory value
// applies when the policy is entirely absent from an older configuration.
DeviceIncidentSeveritySpec device_incident_severity_spec(
    fic::ipc::DeviceIncidentKind kind);

// Builds the IPC acknowledgement the main daemon returns for a device
// violation event of `kind`. This is the PRODUCTION response builder the
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
    fic::ipc::DeviceIncidentKind kind,
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