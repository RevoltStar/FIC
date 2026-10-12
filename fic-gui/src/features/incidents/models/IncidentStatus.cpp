#include "IncidentStatus.h"
#include <stdexcept>
namespace {
QString token(const nlohmann::json& j, const char* field,
              std::initializer_list<const char*> allowed) {
    const auto value = j.at(field).get<std::string>();
    for (auto candidate : allowed) if (value == candidate) return QString::fromStdString(value);
    throw std::runtime_error(std::string("Invalid incident token: ") + field);
}
}
IncidentStatus IncidentStatus::parse(const nlohmann::json& j) {
    IncidentStatus s;
    s.severity = token(j, "severity", {"UNLOCKED", "SOFT", "STANDARD", "HARD", "ISOLATE"});
    s.provenance = token(j, "persistent_provenance", {"PROVEN", "ABSENT", "INVALID_CONTENT", "BROKEN"});
    s.runtime = token(j, "runtime", {"inactive", "applying", "active", "degraded", "clearing"});
    s.mode = token(j, "response_mode", {"OFF", "PASSIVE", "ACTIVE"});
    s.stateProven = j.at("state_proven").get<bool>();
    s.persistentBroken = j.at("persistent_state_broken").get<bool>();
    s.modeProven = j.at("response_mode_proven").get<bool>();
    s.modeDiagnostic = QString::fromStdString(j.at("response_mode_diagnostic").get<std::string>());
    s.detail = QString::fromStdString(j.at("detail").get<std::string>());
    const auto& c = j.at("runtime_containment");
    s.pam = c.at("pam_gate_active").get<bool>();
    s.sessions = c.at("sessions_contained").get<bool>();
    s.userRuntime = c.at("user_runtime_contained").get<bool>();
    s.network = c.at("network_quarantined").get<bool>();
    return s;
}
bool IncidentStatus::normal() const {
    return stateProven && !persistentBroken && provenance == "PROVEN" && modeProven && severity == "UNLOCKED" &&
        runtime == "inactive" && !pam && !sessions && !userRuntime && !network;
}
bool IncidentSnapshot::accept(quint64 sequence, const std::optional<IncidentStatus>& value,
                              const QString& diagnostic, bool daemonReachable, QDateTime now) {
    if (sequence <= lastSequence) return false;
    lastSequence = sequence;
    reachable = daemonReachable;
    error = diagnostic;
    if (value) { status = value; acquired = now; stale = false; }
    else stale = status.has_value();
    return true;
}
