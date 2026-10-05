#ifndef FIC_CORE_INCIDENT_SEVERITY_H
#define FIC_CORE_INCIDENT_SEVERITY_H

#include <optional>
#include <string>

namespace fic::core {

// Severity of the FIC incident (system containment) state.
//
// The ordering declared here IS the security ordering used everywhere:
//   UNLOCKED < SOFT < STANDARD < HARD < ISOLATE
//
// Severity is MONOTONIC: an automated detector may raise it, and only the
// administrative `incident clear` operation may lower it back to UNLOCKED.
// There is deliberately no per-policy severity inheritance anywhere in the
// codebase: each Policy declares its OWN violation_severity.
enum class IncidentSeverity {
    Unlocked = 0,
    Soft = 1,
    Standard = 2,
    Hard = 3,
    Isolate = 4
};

// Strict textual token of a severity. This is the EXACT byte sequence stored
// in the authoritative persistent incident state file (followed by a
// single '\n'). No other formatting is accepted.
std::string incidentSeverityToken(IncidentSeverity severity);

// Strict parser for the authoritative persistent token. Rejects unknown
// tokens, mixed case, padding and every other deviation. Used by the
// fail-closed lockstatus parser; never leniently derived from a substring.
std::optional<IncidentSeverity> parseIncidentSeverityToken(
    const std::string& token);

// Ordering helpers. Numeric comparison of the enum values is the ordering, so
// these are thin named wrappers to make call sites self-documenting.
bool incidentSeverityLess(IncidentSeverity left, IncidentSeverity right);
bool incidentSeverityAtLeast(IncidentSeverity value, IncidentSeverity bound);
IncidentSeverity maxIncidentSeverity(
    IncidentSeverity left, IncidentSeverity right);

// True when the severity keeps the persistent incident state unencumbered.
// ONLY IncidentSeverity::Unlocked qualifies: every other value means the
// incident is present and containment is required.
bool incidentSeverityIsUnlocked(IncidentSeverity severity);

// True when a severity keeps ordinary (non-recovery) logins permitted. This
// mirrors the PAM access gate: only UNLOCKED and SOFT admit an ordinary
// login.
bool incidentSeverityAllowsOrdinaryLogin(IncidentSeverity severity);

// Severity a Policy declares for its own violation. NONE is a deliberate
// "do not react" sentinel and is NOT an IncidentSeverity: it must never be
// compared with, merged into, or persisted as incident state. There is no
// violation severity below SOFT on purpose - a reacting policy always has
// at least a detectable runtime effect.
enum class ViolationSeverity {
    None = 0,
    Soft = 1,
    Standard = 2,
    Hard = 3,
    Isolate = 4
};

std::string violationSeverityToken(ViolationSeverity severity);
std::optional<ViolationSeverity> parseViolationSeverityToken(
    const std::string& token);

// False only for ViolationSeverity::None.
bool violationSeverityReacts(ViolationSeverity severity);

// The incident severity a violating policy raises to. Undefined (throws
// std::invalid_argument) for ViolationSeverity::None: callers must check
// violationSeverityReacts() first. Storing this in a bare IncidentSeverity
// keeps "NONE means Unlocked" structurally impossible.
IncidentSeverity violationSeverityToIncidentSeverity(
    ViolationSeverity severity);

} // namespace fic::core

#endif // FIC_CORE_INCIDENT_SEVERITY_H