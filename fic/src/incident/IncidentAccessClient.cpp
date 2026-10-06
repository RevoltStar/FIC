#include "incident/IncidentAccessClient.h"

#include <fic/ipc/FicIpcClient.h>
#include <fic/core/incident/IncidentSeverity.h>

#include <chrono>

namespace fic::incident {
namespace {
IncidentAccessReply queryPath(const std::string& path, uid_t expectedPeerUid) {
    const fic::ipc::Client client(path, std::chrono::seconds(2), expectedPeerUid);
    const auto result = client.requestWithStatus({{"command", "access_gate_status"}});
    if (!result.hasResponse) return {false, result.error};
    const auto& response = result.response;
    if (!response.is_object() || response.size() != 8 ||
        !response.contains("ok") || !response["ok"].is_boolean() ||
        !response["ok"].get<bool>() ||
        !response.contains("message") || !response["message"].is_string() ||
        !response.contains("daemon_state") || !response["daemon_state"].is_string() ||
        !response.contains("severity") || !response["severity"].is_string() ||
        !response.contains("persistent_state_proven") ||
        !response["persistent_state_proven"].is_boolean() ||
        !response.contains("persistent_provenance") ||
        !response["persistent_provenance"].is_string() ||
        !response.contains("ordinary_login_allowed") ||
        !response["ordinary_login_allowed"].is_boolean()) {
        return {false, "invalid access gate response fields"};
    }
    const std::string state = response["daemon_state"].get<std::string>();
    const std::string provenance = response["persistent_provenance"].get<std::string>();
    const auto severity = ::fic::core::parseIncidentSeverityToken(
        response["severity"].get<std::string>());
    const bool proven = response["persistent_state_proven"].get<bool>();
    const bool claimed = response["ordinary_login_allowed"].get<bool>();
    const bool validState = state == "INITIALIZING" || state == "APPLYING" ||
        state == "READY" || state == "STOPPING";
    const bool validProvenance = provenance == "PROVEN" || provenance == "ABSENT" ||
        provenance == "INVALID_CONTENT" || provenance == "BROKEN";
    const bool computed = state == "READY" && proven && severity.has_value() &&
        (*severity == ::fic::core::IncidentSeverity::Unlocked ||
         *severity == ::fic::core::IncidentSeverity::Soft);
    if (!validState || !validProvenance || !severity.has_value() ||
        proven != (provenance == "PROVEN") || claimed != computed ||
        (!proven && *severity != ::fic::core::IncidentSeverity::Isolate)) {
        return {false, "inconsistent access gate response"};
    }
    return {computed, computed ? "access allowed" : "incident access denied"};
}
} // namespace

IncidentAccessReply IncidentAccessClient::query() {
    return queryPath(fic::ipc::path_defaults::DAEMON_SOCKET, 0);
}

IncidentAccessReply IncidentAccessClient::queryAtPathForTests(
    const std::string& path, uid_t expectedPeerUid) {
    return queryPath(path, expectedPeerUid);
}

} // namespace fic::incident
