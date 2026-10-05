#include <fic/core/incident/IncidentSeverity.h>

#include <stdexcept>

namespace fic::core {
namespace {

struct SeverityToken {
    IncidentSeverity severity;
    const char* token;
};

// Single authoritative table for the persistent token mapping. Both the
// writer and the fail-closed parser go through this table, so a stored value
// can never be spelled two ways.
constexpr SeverityToken kIncidentTokens[] = {
    {IncidentSeverity::Unlocked, "UNLOCKED"},
    {IncidentSeverity::Soft, "SOFT"},
    {IncidentSeverity::Standard, "STANDARD"},
    {IncidentSeverity::Hard, "HARD"},
    {IncidentSeverity::Isolate, "ISOLATE"},
};

constexpr SeverityToken kViolationTokens[] = {
    {IncidentSeverity::Unlocked, "NONE"},
    {IncidentSeverity::Soft, "SOFT"},
    {IncidentSeverity::Standard, "STANDARD"},
    {IncidentSeverity::Hard, "HARD"},
    {IncidentSeverity::Isolate, "ISOLATE"},
};

} // namespace

std::string incidentSeverityToken(IncidentSeverity severity) {
    for (const SeverityToken& entry : kIncidentTokens) {
        if (entry.severity == severity) {
            return entry.token;
        }
    }
    throw std::invalid_argument("unknown incident severity value");
}

std::optional<IncidentSeverity> parseIncidentSeverityToken(
    const std::string& token) {
    for (const SeverityToken& entry : kIncidentTokens) {
        if (token == entry.token) {
            return entry.severity;
        }
    }
    return std::nullopt;
}

bool incidentSeverityLess(IncidentSeverity left, IncidentSeverity right) {
    return static_cast<int>(left) < static_cast<int>(right);
}

bool incidentSeverityAtLeast(IncidentSeverity value, IncidentSeverity bound) {
    return static_cast<int>(value) >= static_cast<int>(bound);
}

IncidentSeverity maxIncidentSeverity(
    IncidentSeverity left, IncidentSeverity right) {
    return incidentSeverityLess(left, right) ? right : left;
}

bool incidentSeverityIsUnlocked(IncidentSeverity severity) {
    return severity == IncidentSeverity::Unlocked;
}

bool incidentSeverityAllowsOrdinaryLogin(IncidentSeverity severity) {
    return severity == IncidentSeverity::Unlocked ||
           severity == IncidentSeverity::Soft;
}

std::string violationSeverityToken(ViolationSeverity severity) {
    for (const SeverityToken& entry : kViolationTokens) {
        if (static_cast<ViolationSeverity>(entry.severity) == severity) {
            return entry.token;
        }
    }
    throw std::invalid_argument("unknown violation severity value");
}

std::optional<ViolationSeverity> parseViolationSeverityToken(
    const std::string& token) {
    for (const SeverityToken& entry : kViolationTokens) {
        if (token == entry.token) {
            return static_cast<ViolationSeverity>(entry.severity);
        }
    }
    return std::nullopt;
}

bool violationSeverityReacts(ViolationSeverity severity) {
    return severity != ViolationSeverity::None;
}

IncidentSeverity violationSeverityToIncidentSeverity(
    ViolationSeverity severity) {
    if (!violationSeverityReacts(severity)) {
        // NONE is not an incident severity. Converting it would silently
        // fabricate an UNLOCKED incident, so the mapping is rejected instead.
        throw std::invalid_argument(
            "violation severity NONE does not map to an incident severity");
    }
    return static_cast<IncidentSeverity>(severity);
}

} // namespace fic::core
