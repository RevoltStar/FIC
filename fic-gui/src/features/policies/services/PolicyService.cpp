#include "features/policies/services/PolicyService.h"

#include <utility>

#include <nlohmann/json.hpp>

#include <fic/ipc/FicIpcClient.h>

namespace {
bool requireResponseEnvelope(const PolicyService::RequestResult& requestResult,
                               const char* operation,
                               bool requireSuccess,
                               nlohmann::json& response,
                               QString& error)
{
    if (!requestResult.hasResponse) {
        error = QString::fromStdString(requestResult.error);
        return false;
    }
    response = requestResult.response;
    if (!response.is_object() || !response.contains("ok") ||
        !response["ok"].is_boolean() || !response.contains("message") ||
        !response["message"].is_string()) {
        error = QString("%1 protocol error: daemon response must contain boolean ok and string message")
            .arg(operation);
        return false;
    }
    if (requireSuccess && !response["ok"].get<bool>()) {
        error = QString::fromStdString(response["message"].get<std::string>());
        return false;
    }
    return true;
}

bool requireApplyResponse(const PolicyService::RequestResult& requestResult,
                          nlohmann::json& response,
                          QString& error)
{
    if (!requireResponseEnvelope(
            requestResult, "apply_module", false, response, error)) {
        return false;
    }
    const bool malformed =
        (response.contains("summary") && !response["summary"].is_object()) ||
        (response.contains("results") && !response["results"].is_array()) ||
        (response.contains("diagnostics_truncated") &&
         !response["diagnostics_truncated"].is_boolean());
    if (malformed) {
        error = "apply_module protocol error: invalid result fields";
        return false;
    }
    if (response.contains("summary")) {
        const auto& summary = response["summary"];
        for (const char* field : {
                 "total", "applied", "failed", "disabled", "not_found"}) {
            if (summary.contains(field) && !summary[field].is_number_integer()) {
                error = "apply_module protocol error: invalid summary";
                return false;
            }
        }
    }
    for (const auto& item : response.value("results", nlohmann::json::array())) {
        if (!item.is_object() ||
            (item.contains("diagnostics") && !item["diagnostics"].is_array()) ||
            (item.contains("diagnostics_truncated") &&
             !item["diagnostics_truncated"].is_boolean())) {
            error = "apply_module protocol error: invalid policy result";
            return false;
        }
        for (const char* field : {
                 "module", "submodule", "policy", "status", "message"}) {
            if (item.contains(field) && !item[field].is_string()) {
                error = "apply_module protocol error: invalid policy result";
                return false;
            }
        }
        for (const auto& diagnostic : item.value(
                 "diagnostics", nlohmann::json::array())) {
            if (!diagnostic.is_object()) {
                error = "apply_module protocol error: invalid diagnostic";
                return false;
            }
            for (const char* field : {
                     "timestamp", "level", "category", "message"}) {
                if (diagnostic.contains(field) &&
                    !diagnostic[field].is_string()) {
                    error = "apply_module protocol error: invalid diagnostic";
                    return false;
                }
            }
        }
    }
    return true;
}
}

PolicyService::PolicyService(RequestFunction request)
    : request_(std::move(request))
{
}

PolicyService::RequestResult PolicyService::request(
    const nlohmann::json& payload) const
{
    if (request_) {
        return request_(payload);
    }
    return fic::ipc::Client().requestWithStatus(payload);
}

bool PolicyService::loadModules(
    std::vector<ModuleDescriptor>& modules,
    QString& error) const
{
    const auto requestResult = request({{"command", "module_list"}});
    if (!requestResult.hasResponse) {
        error = QString::fromStdString(requestResult.error);
        return false;
    }
    std::string parseError;
    const bool ok = parseModuleDescriptors(
        requestResult.response, modules, parseError);
    error = QString::fromStdString(parseError);
    return ok;
}

bool PolicyService::loadPolicies(
    const std::string& module,
    std::vector<PolicyDescriptor>& policies,
    QString& error) const
{
    const auto requestResult = request({
        {"command", "policy_list"}, {"module", module}
    });
    if (!requestResult.hasResponse) {
        error = QString::fromStdString(requestResult.error);
        return false;
    }
    std::string parseError;
    const bool ok = parsePolicyDescriptors(
        requestResult.response, module, policies, parseError);
    error = QString::fromStdString(parseError);
    return ok;
}

bool PolicyService::saveChanges(
    const std::string& module,
    const std::vector<PolicyChange>& changes,
    QString& error) const
{
    error.clear();
    for (const PolicyChange& change : changes) {
        if (change.valueConfigurable) {
            const auto requestResult = request({
                {"command", "set_policy_value"},
                {"module", module},
                {"policy", change.policyName},
                {"value", change.value}
            });
            nlohmann::json response;
            if (!requireResponseEnvelope(
                    requestResult, "set_policy_value", true, response, error)) {
                return false;
            }
        }
        const auto requestResult = request({
            {"command", change.enabled ? "enable_policy" : "disable_policy"},
            {"module", module},
            {"policy", change.policyName}
        });
        nlohmann::json response;
        if (!requireResponseEnvelope(
                requestResult,
                change.enabled ? "enable_policy" : "disable_policy",
                true, response, error)) {
            return false;
        }
    }
    return true;
}

PolicyService::ApplyResult PolicyService::saveAndApplyChanges(
    const std::string& module,
    const std::vector<PolicyChange>& changes) const
{
    ApplyResult result;
    if (!saveChanges(module, changes, result.error)) {
        return result;
    }
    const RequestResult requestResult = request(
        {{"command", "apply_module"}, {"module", module}});
    if (!requireApplyResponse(requestResult, result.response, result.error)) {
        result.response = nlohmann::json();
        return result;
    }
    result.status = ApplyStatus::Completed;
    return result;
}
