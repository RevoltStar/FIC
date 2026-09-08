#ifndef FIC_DAEMON_ADMIN_AUDIT_H
#define FIC_DAEMON_ADMIN_AUDIT_H

#include <string>

#include <nlohmann/json_fwd.hpp>

#include <fic/core/logging/SecurityAudit.h>

std::string admin_audit_command(const nlohmann::json& request);
nlohmann::json admin_audit_request_fields(const nlohmann::json& request);
nlohmann::json make_admin_ipc_audit_event(
    const fic::core::security_audit::PeerCredentials& peer,
    const nlohmann::json& request,
    const nlohmann::json& response);
nlohmann::json make_admin_ipc_audit_event(
    const fic::core::security_audit::PeerCredentials& peer,
    const nlohmann::json& request,
    const nlohmann::json& response,
    const std::string& timestamp);

#endif // FIC_DAEMON_ADMIN_AUDIT_H
