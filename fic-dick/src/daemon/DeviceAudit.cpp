#include "daemon/DeviceAudit.h"

#include <nlohmann/json.hpp>

namespace fic::device_control {
namespace {

using json = nlohmann::json;

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

bool is_mutating_device_command(const std::string& command) {
    return command == "udev_event" ||
           command == "device_reconcile" ||
           command == "device_update_control_level" ||
           command == "device_update_ignore_hierarchy" ||
           command == "device_update_children_control" ||
           command == "device_regenerate_policy" ||
           command == "device_reset_control" ||
           command == "device_delete" ||
           command == "device_check_permanent" ||
           command == "shutdown";
}

std::string device_audit_command(const json& request) {
    if (!request.is_object()) {
        return "<invalid-json>";
    }
    if (!request.contains("command") || !request["command"].is_string()) {
        return "<invalid-command>";
    }
    return request["command"].get<std::string>();
}

json device_audit_request_fields(const json& request) {
    json fields = json::object();
    if (!request.is_object()) {
        return fields;
    }

    for (const char* field : {
             "action", "devpath", "subsystem", "control_level", "children_control"}) {
        if (request.contains(field) && request[field].is_string()) {
            fields[field] = request[field].get<std::string>();
        }
    }
    for (const char* field : {"device_id", "parent_id"}) {
        if (request.contains(field) && request[field].is_number_integer()) {
            fields[field] = request[field];
        }
    }
    for (const char* field : {
             "ignore_hierarchy", "block_usb_storage", "block_printers_scanners",
             "block_optical_drives"}) {
        if (request.contains(field) && request[field].is_boolean()) {
            fields[field] = request[field].get<bool>();
        }
    }
    return fields;
}

json make_device_ipc_audit_event(
    const fic::core::security_audit::PeerCredentials& peer,
    const json& request,
    const json& response) {
    return fic::core::security_audit::makeIpcEvent(
        "fic-dick", peer, device_audit_command(request),
        device_audit_request_fields(request), response_ok(response),
        response_message(response));
}

json make_device_ipc_audit_event(
    const fic::core::security_audit::PeerCredentials& peer,
    const json& request,
    const json& response,
    const std::string& timestamp) {
    return fic::core::security_audit::makeIpcEvent(
        "fic-dick", peer, device_audit_command(request),
        device_audit_request_fields(request), response_ok(response),
        response_message(response), timestamp);
}

} // namespace fic::device_control
