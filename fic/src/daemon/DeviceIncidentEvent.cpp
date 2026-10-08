#include "daemon/DeviceIncidentEvent.h"

#include <fic/core/config/ModuleConfigFileHandler.h>

namespace fic::daemon {

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