#include "incident/IncidentAccessClient.h"

#include <fic/ipc/FicIpcClient.h>
#include <fic/ipc/FicReadinessStatus.h>
#include <fic/core/incident/IncidentSeverity.h>

#include <chrono>

namespace fic::incident {
namespace {
IncidentAccessReply queryPath(const std::string& path, uid_t expectedPeerUid) {
    const fic::ipc::Client client(path, std::chrono::seconds(2), expectedPeerUid);
    const auto result = client.requestWithStatus({{"command", "access_gate_status"}});
    if (!result.hasResponse) return {false, result.error};
    fic::ipc::AccessGateStatus status;
    std::string error;
    if (!fic::ipc::parseAccessGateStatus(result.response, status, error)) return {false, error};
    return {status.loginAllowed, status.loginAllowed ? "access allowed" : "incident access denied"};
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
