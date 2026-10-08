#include "daemon/DeviceIncidentEvent.h"

#include <fic/core/config/ModuleConfigFileHandler.h>

#include <nlohmann/json.hpp>

namespace fic::daemon {

namespace {

// The message must describe the ACTUAL persistence outcome: a durably
// recorded severity with a failed containment is a recorded incident with a
// degraded containment, never a recording failure.
std::string raiseMessage(bool persistenceConfirmed, bool degraded) {
    if (!persistenceConfirmed) {
        return "device incident could not be recorded";
    }
    return degraded
        ? "device incident recorded; containment degraded"
        : "device incident processed";
}

} // namespace

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
    const std::string& detail) {
    if (ignoredByMode ||
        reaction.kind == DeviceMissingReactionKind::Disabled ||
        reaction.kind == DeviceMissingReactionKind::None) {
        // An intentional ignore closes the delivery obligation without any
        // incident write: no new persistence obligation exists, so
        // persistence_confirmed=false is the correct, non-error answer.
        return json{
            {"ok", true},
            {"message", "device incident intentionally ignored"},
            {"command", "incident_device_missing"},
            {"acknowledged", true},
            {"persistence_confirmed", false},
            {"incident_ok", true},
            {"escalated", false},
            {"reason", reaction.diagnostic},
            {"response_mode", responseModeToken},
            {"requested_severity", "NONE"},
            {"effective_severity", effectiveSeverityToken},
            {"ignored", true},
            {"runtime", runtimeToken},
            {"api_version", 1}};
    }
    return json{
        {"ok", incidentOk},
        {"message", raiseMessage(persistenceConfirmed,
                                 runtimeToken == "degraded")},
        {"command", "incident_device_missing"},
        {"acknowledged", persistenceConfirmed},
        {"persistence_confirmed", persistenceConfirmed},
        {"incident_ok", incidentOk},
        {"escalated", escalated},
        {"reason", reaction.diagnostic},
        {"response_mode", responseModeToken},
        {"requested_severity", requestedSeverityToken},
        {"effective_severity", effectiveSeverityToken},
        {"ignored", false},
        {"persistent_state_broken", persistentStateBroken},
        {"runtime", runtimeToken},
        {"detail", detail},
        {"api_version", 1}};
}

DeviceMissingReaction resolve_device_missing_severity(Policy& policy) {
    DeviceMissingReaction reaction;
    // The status must be PROVEN ENABLE or DISABLE. ModuleConfigFileHandler
    // silently normalizes every other spelling to DISABLE, and a malformed
    // security-critical status must never be read as an intentional disable,
    // so the RAW status entry is re-read here with the same trusted
    // configuration reader the daemon configuration was built from.
    {
        ModuleConfigFileHandler rawStatusReader(
            policy.moduleName);
        if (!rawStatusReader.loadConfig()) {
            reaction.diagnostic =
                "permanent_device_missing_severity is unproven; "
                "fail-closed reaction ISOLATE";
            return reaction;
        }
        const auto status = rawStatusReader.entries().find(
            policy.policyName + ".status");
        if (status == rawStatusReader.entries().end() ||
            (status->second != "ENABLE" && status->second != "DISABLE")) {
            reaction.diagnostic =
                "permanent_device_missing_severity is unproven; "
                "fail-closed reaction ISOLATE";
            return reaction;
        }
    }
    if (!policy.isEnabled()) {
        reaction.kind = DeviceMissingReactionKind::Disabled;
        reaction.severity = ::fic::core::IncidentSeverity::Unlocked;
        reaction.diagnostic = "permanent_device_missing_severity is DISABLE";
        return reaction;
    }
    const std::optional<std::string> value = policy.getValue();
    if (!value.has_value()) {
        // Fail closed, never silently NONE: an unparsable security-critical
        // value must not degrade the reaction.
        reaction.diagnostic =
            "permanent_device_missing_severity is unproven; "
            "fail-closed reaction ISOLATE";
        return reaction;
    }
    // The setting uses the VIOLATION severity token family (NONE | SOFT |
    // STANDARD | HARD | ISOLATE), exactly like Policy::violation_severity.
    const auto violation =
        ::fic::core::parseViolationSeverityToken(value.value());
    if (!violation.has_value()) {
        // Fail closed, never silently NONE: an unparsable security-critical
        // value must not degrade the reaction.
        reaction.diagnostic =
            "permanent_device_missing_severity is unproven; "
            "fail-closed reaction ISOLATE";
        return reaction;
    }
    if (!::fic::core::violationSeverityReacts(*violation)) {
        reaction.kind = DeviceMissingReactionKind::None;
        reaction.severity = ::fic::core::IncidentSeverity::Unlocked;
        reaction.diagnostic = "permanent_device_missing_severity is NONE";
        return reaction;
    }
    reaction.kind = DeviceMissingReactionKind::Severity;
    reaction.severity =
        ::fic::core::violationSeverityToIncidentSeverity(*violation);
    reaction.diagnostic = "configured " + value.value();
    return reaction;
}

} // namespace fic::daemon