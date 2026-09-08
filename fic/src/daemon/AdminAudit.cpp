#include "daemon/AdminAudit.h"

#include <utility>

#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace {

bool response_ok(const json& response) {
    return response.is_object() && response.contains("ok") &&
           response["ok"].is_boolean() && response["ok"].get<bool>();
}

std::string response_message(const json& response) {
    if (response.is_object() && response.contains("message") &&
        response["message"].is_string()) {
        return response["message"].get<std::string>();
    }
    return {};
}

} // namespace

std::string admin_audit_command(const json& request) {
    if (!request.is_object()) {
        return "<invalid-json>";
    }
    if (!request.contains("command") || !request["command"].is_string()) {
        return "<invalid-command>";
    }
    return request["command"].get<std::string>();
}

json admin_audit_request_fields(const json& request) {
    json fields = json::object();
    if (!request.is_object()) {
        return fields;
    }

    for (const char* field : {"module", "policy", "control_level"}) {
        if (request.contains(field) && request[field].is_string()) {
            fields[field] = request[field].get<std::string>();
        }
    }
    for (const char* field : {"device_id", "parent_id"}) {
        if (request.contains(field) && request[field].is_number_integer()) {
            fields[field] = request[field];
        }
    }
    return fields;
}

json make_admin_ipc_audit_event(
    const fic::core::security_audit::PeerCredentials& peer,
    const json& request,
    const json& response) {
    return fic::core::security_audit::makeIpcEvent(
        "fic", peer, admin_audit_command(request),
        admin_audit_request_fields(request), response_ok(response),
        response_message(response));
}

json make_admin_ipc_audit_event(
    const fic::core::security_audit::PeerCredentials& peer,
    const json& request,
    const json& response,
    const std::string& timestamp) {
    return fic::core::security_audit::makeIpcEvent(
        "fic", peer, admin_audit_command(request),
        admin_audit_request_fields(request), response_ok(response),
        response_message(response), timestamp);
}
