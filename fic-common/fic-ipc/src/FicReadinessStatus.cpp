#include <fic/ipc/FicReadinessStatus.h>
#include <algorithm>
#include <cctype>

namespace fic::ipc {
namespace {
bool known(const std::string& value, std::initializer_list<const char*> tokens) {
    return std::any_of(tokens.begin(), tokens.end(), [&](const char* token) { return value == token; });
}
bool validate(const AccessGateStatus& s) {
    return known(s.state, {"INITIALIZING", "APPLYING", "READY", "DEGRADED", "STOPPING"}) &&
        known(s.mode, {"OFF", "PASSIVE", "ACTIVE"}) && (s.modeProven || s.mode == "ACTIVE") &&
        known(s.severity, {"UNLOCKED", "SOFT", "STANDARD", "HARD", "ISOLATE"}) &&
        known(s.provenance, {"PROVEN", "ABSENT", "INVALID_CONTENT", "BROKEN"}) &&
        s.stateProven == (s.provenance == "PROVEN") && (s.stateProven || s.severity == "ISOLATE") &&
        s.loginAllowed == computedLoginAllowed(s);
}
bool accessFields(const json& value, AccessGateStatus& s) {
    if (!value.at("api_version").is_number_integer() || value.at("api_version") != API_VERSION ||
        !value.at("ok").is_boolean() || !value.at("ok").get<bool>() ||
        !value.at("message").is_string() || value.at("message").get_ref<const std::string&>().size() > 4096 ||
        !value.at("response_mode_proven").is_boolean() ||
        !value.at("persistent_state_proven").is_boolean() || !value.at("ordinary_login_allowed").is_boolean()) return false;
    s.state = value.at("daemon_state").get<std::string>();
    s.mode = value.at("response_mode").get<std::string>();
    s.modeProven = value.at("response_mode_proven").get<bool>();
    s.severity = value.at("severity").get<std::string>();
    s.stateProven = value.at("persistent_state_proven").get<bool>();
    s.provenance = value.at("persistent_provenance").get<std::string>();
    s.loginAllowed = value.at("ordinary_login_allowed").get<bool>();
    return validate(s);
}
}
bool computedLoginAllowed(const AccessGateStatus& s) {
    return s.modeProven && (s.mode != "ACTIVE" || (s.state == "READY" && s.stateProven &&
        (s.severity == "UNLOCKED" || s.severity == "SOFT")));
}
json serializeAccessGateStatus(const AccessGateStatus& s) {
    return {{"api_version", API_VERSION}, {"ok", true}, {"message", "incident access gate status"},
        {"daemon_state", s.state}, {"response_mode", s.mode}, {"response_mode_proven", s.modeProven},
        {"severity", s.severity}, {"persistent_state_proven", s.stateProven},
        {"persistent_provenance", s.provenance}, {"ordinary_login_allowed", s.loginAllowed}};
}
json serializePreLoginStatus(const PreLoginStatus& s) {
    auto value = serializeAccessGateStatus(s.access);
    value["message"] = "prelogin status";
    value["startup_apply_started"] = s.started;
    value["startup_apply_completed"] = s.completed;
    value["startup_apply_ok"] = s.applyOk;
    value["startup_lifecycle_completed"] = s.lifecycleCompleted;
    value["diagnostic"] = s.diagnostic.substr(0, 4096);
    value["boot_id"] = s.bootId;
    value["daemon_pid"] = s.daemonPid;
    return value;
}
bool parseAccessGateStatus(const json& value, AccessGateStatus& s, std::string& error) {
    try {
        if (value.is_object() && value.size() == 10 && accessFields(value, s)) { error.clear(); return true; }
    } catch (const json::exception&) {}
    error = "invalid/inconsistent access gate response"; return false;
}
bool validBootId(const std::string& value) {
    if (value.size() != 36) return false;
    for (std::size_t i = 0; i < value.size(); ++i)
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (value[i] != '-') return false;
        } else if (!(value[i] >= '0' && value[i] <= '9') && !(value[i] >= 'a' && value[i] <= 'f')) return false;
    return true;
}
bool parsePreLoginStatus(const json& value, PreLoginStatus& s, std::string& error) {
    try {
        if (!value.is_object() || value.size() != 17 || !accessFields(value, s.access)) throw std::runtime_error("fields");
        for (const auto key : {"startup_apply_started", "startup_apply_completed", "startup_apply_ok", "startup_lifecycle_completed"})
            if (!value.at(key).is_boolean()) throw std::runtime_error("type");
        s.started = value.at("startup_apply_started").get<bool>();
        s.completed = value.at("startup_apply_completed").get<bool>();
        s.applyOk = value.at("startup_apply_ok").get<bool>();
        s.lifecycleCompleted = value.at("startup_lifecycle_completed").get<bool>();
        s.diagnostic = value.at("diagnostic").get<std::string>();
        s.bootId = value.at("boot_id").get<std::string>();
        if (!value.at("daemon_pid").is_number_integer()) throw std::runtime_error("pid type");
        const auto pid = value.at("daemon_pid").get<std::int64_t>();
        if (pid <= 0 || pid > 2147483647) throw std::runtime_error("pid range");
        s.daemonPid = static_cast<int>(pid);
        if (!validBootId(s.bootId) || s.diagnostic.size() > 4096 || s.diagnostic.find('\0') != std::string::npos ||
            (s.completed && !s.started) || (s.applyOk && !s.completed) ||
            (s.lifecycleCompleted && !s.completed) || (s.access.state == "READY" && !s.lifecycleCompleted))
            throw std::runtime_error("consistency");
        error.clear(); return true;
    } catch (const std::exception&) {
        error = "invalid/inconsistent prelogin response"; return false;
    }
}
bool mayAutoHandoff(const PreLoginStatus& s, const std::string& boot) {
    return validate(s.access) && validBootId(boot) && s.bootId == boot && s.daemonPid > 0 &&
        s.started && s.completed && s.applyOk && s.lifecycleCompleted && s.access.modeProven &&
        s.access.state == "READY" && s.access.loginAllowed;
}
}
