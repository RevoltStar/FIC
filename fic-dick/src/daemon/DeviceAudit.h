#ifndef FIC_DICK_DAEMON_DEVICE_AUDIT_H
#define FIC_DICK_DAEMON_DEVICE_AUDIT_H

#include <string>

#include <nlohmann/json_fwd.hpp>

#include <fic/core/logging/SecurityAudit.h>

namespace fic::device_control {

bool is_mutating_device_command(const std::string& command);
std::string device_audit_command(const nlohmann::json& request);
nlohmann::json device_audit_request_fields(const nlohmann::json& request);
nlohmann::json make_device_ipc_audit_event(
    const fic::core::security_audit::PeerCredentials& peer,
    const nlohmann::json& request,
    const nlohmann::json& response);
nlohmann::json make_device_ipc_audit_event(
    const fic::core::security_audit::PeerCredentials& peer,
    const nlohmann::json& request,
    const nlohmann::json& response,
    const std::string& timestamp);

} // namespace fic::device_control

#endif // FIC_DICK_DAEMON_DEVICE_AUDIT_H
