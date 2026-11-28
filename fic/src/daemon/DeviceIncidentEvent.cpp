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
    const std::string& detail) {
    const std::string command = fic::ipc::deviceIncidentCommand(kind);
    if (ignoredByMode ||
        reaction.kind == DeviceMissingReactionKind::Disabled ||
        reaction.kind == DeviceMissingReactionKind::None) {
        // An intentional ignore closes the delivery obligation without any
        // incident write: no new persistence obligation exists, so
        // persistence_confirmed=false is the correct, non-error answer.
        return json{
            {"ok", true},
            {"message", "device incident intentionally ignored"},
            {"command", command},
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
        {"command", command},
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

DeviceIncidentSeveritySpec device_incident_severity_spec(
    fic::ipc::DeviceIncidentKind kind) {
    DeviceIncidentSeveritySpec spec;
    spec.policyName = fic::ipc::deviceIncidentSeverityPolicy(kind);
    if (kind != fic::ipc::DeviceIncidentKind::PermanentDeviceMissing) {
        // The two newer detector settings are appended to existing
        // configurations by the additive `ensure-config` upgrade step. An
        // installation that predates them therefore has no entry at all, and
        // must use the packaged factory value instead of failing closed to
        // ISOLATE. A present but unprovable entry still fails closed.
        spec.factoryDefaultForAbsentPolicy =
            fic::ipc::deviceIncidentFactorySeverity(kind);
    }
    return spec;
}

DeviceMissingReaction resolve_device_missing_severity(Policy& policy) {
    return resolve_device_incident_severity(
        policy, DeviceIncidentSeveritySpec{policy.policyName, std::nullopt});
}

DeviceMissingReaction resolve_device_incident_severity(
    Policy& policy, const DeviceIncidentSeveritySpec& spec) {
    DeviceMissingReaction reaction;
    const std::string& policyName = spec.policyName;
    const auto failClosed = [&]() {
        reaction.kind = DeviceMissingReactionKind::Unproven;
        reaction.severity = ::fic::core::IncidentSeverity::Isolate;
        reaction.diagnostic =
            policyName + " is unproven; fail-closed reaction ISOLATE";
        return reaction;
    };
    // The status must be PROVEN ENABLE or DISABLE. ModuleConfigFileHandler
    // silently normalizes every other spelling to DISABLE, and a malformed
    // security-critical status must never be read as an intentional disable,
    // so the RAW status entry is re-read here with the same trusted
    // configuration reader the daemon configuration was built from.
    {
        ModuleConfigFileHandler rawStatusReader(policy.moduleName);
        if (!rawStatusReader.loadConfig()) {
            return failClosed();
        }
        const auto entries = rawStatusReader.entries();
        const auto status = entries.find(policyName + ".status");
        if (status == entries.end()) {
            // A completely unconfigured policy (no status AND no value) is a
            // configuration that predates this setting. Use the packaged
            // factory value; anything partially present is unproven.
            const bool valueAbsent =
                entries.find(policyName + ".value") == entries.end();
            if (valueAbsent && spec.factoryDefaultForAbsentPolicy.has_value()) {
                const auto factory = ::fic::core::parseViolationSeverityToken(
                    *spec.factoryDefaultForAbsentPolicy);
                if (!factory.has_value()) {
                    return failClosed();
                }
                if (!::fic::core::violationSeverityReacts(*factory)) {
                    reaction.kind = DeviceMissingReactionKind::None;
                    reaction.severity = ::fic::core::IncidentSeverity::Unlocked;
                    reaction.diagnostic = policyName +
                        " is absent from the configuration; factory default " +
                        *spec.factoryDefaultForAbsentPolicy;
                    return reaction;
                }
                reaction.kind = DeviceMissingReactionKind::Severity;
                reaction.severity =
                    ::fic::core::violationSeverityToIncidentSeverity(*factory);
                reaction.diagnostic = policyName +
                    " is absent from the configuration; factory default " +
                    *spec.factoryDefaultForAbsentPolicy;
                return reaction;
            }
            return failClosed();
        }
        if (status->second != "ENABLE" && status->second != "DISABLE") {
            return failClosed();
        }
    }
    if (!policy.isEnabled()) {
        reaction.kind = DeviceMissingReactionKind::Disabled;
        reaction.severity = ::fic::core::IncidentSeverity::Unlocked;
        reaction.diagnostic = policyName + " is DISABLE";
        return reaction;
    }
    const std::optional<std::string> value = policy.getValue();
    if (!value.has_value()) {
        // Fail closed, never silently NONE: an unparsable security-critical
        // value must not degrade the reaction.
        return failClosed();
    }
    // The setting uses the VIOLATION severity token family (NONE | SOFT |
    // STANDARD | HARD | ISOLATE), exactly like Policy::violation_severity.
    const auto violation =
        ::fic::core::parseViolationSeverityToken(value.value());
    if (!violation.has_value()) {
        // Fail closed, never silently NONE: an unparsable security-critical
        // value must not degrade the reaction.
        return failClosed();
    }
    if (!::fic::core::violationSeverityReacts(*violation)) {
        reaction.kind = DeviceMissingReactionKind::None;
        reaction.severity = ::fic::core::IncidentSeverity::Unlocked;
        reaction.diagnostic = policyName + " is NONE";
        return reaction;
    }
    reaction.kind = DeviceMissingReactionKind::Severity;
    reaction.severity =
        ::fic::core::violationSeverityToIncidentSeverity(*violation);
    reaction.diagnostic = "configured " + value.value();
    return reaction;
}

} // namespace fic::daemon