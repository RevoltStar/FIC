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

} // namespace fic::daemon

#endif // FIC_DAEMON_DEVICE_INCIDENT_EVENT_H