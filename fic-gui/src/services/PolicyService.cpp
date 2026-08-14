#include "services/PolicyService.h"

#include <utility>

#include <nlohmann/json.hpp>

#include <fic/ipc/FicIpcClient.h>

namespace {
bool requireSuccessfulResponse(const nlohmann::json& response,
                               const char* operation,
                               QString& error)
{
    if (!response.is_object() || !response.contains("ok") ||
        !response["ok"].is_boolean() || !response.contains("message") ||
        !response["message"].is_string()) {
        error = QString("%1 protocol error: daemon response must contain boolean ok and string message")
            .arg(operation);
        return false;
    }
    if (!response["ok"].get<bool>()) {
        error = QString::fromStdString(response["message"].get<std::string>());
        return false;
    }
    return true;
}
}

PolicyService::PolicyService(RequestFunction request)
    : request_(std::move(request))
{
}

nlohmann::json PolicyService::request(const nlohmann::json& payload) const
{
    if (request_) {
        return request_(payload);
    }
    return fic::ipc::Client().request(payload);
}

bool PolicyService::loadModules(
    std::vector<ModuleDescriptor>& modules,
    QString& error) const
{
    const auto response = request({{"command", "module_list"}});
    std::string parseError;
    const bool ok = parseModuleDescriptors(response, modules, parseError);
    error = QString::fromStdString(parseError);
    return ok;
}

bool PolicyService::loadPolicies(
    const std::string& module,
    std::vector<PolicyDescriptor>& policies,
    QString& error) const
{
    const auto response = request({
        {"command", "policy_list"}, {"module", module}
    });
    std::string parseError;
    const bool ok = parsePolicyDescriptors(response, module, policies, parseError);
    error = QString::fromStdString(parseError);
    return ok;
}

bool PolicyService::applyChanges(
    const std::string& module,
    const std::vector<PolicyChange>& changes,
    nlohmann::json& applyResponse,
    QString& error) const
{
    error.clear();
    applyResponse = nlohmann::json();
    for (const PolicyChange& change : changes) {
        if (change.valueConfigurable) {
            const auto response = request({
                {"command", "set_policy_value"},
                {"module", module},
                {"policy", change.policyName},
                {"value", change.value}
            });
            if (!requireSuccessfulResponse(response, "set_policy_value", error)) {
                return false;
            }
        }
        const auto response = request({
            {"command", change.enabled ? "enable_policy" : "disable_policy"},
            {"module", module},
            {"policy", change.policyName}
        });
        if (!requireSuccessfulResponse(
                response,
                change.enabled ? "enable_policy" : "disable_policy",
                error)) {
            return false;
        }
    }
    applyResponse = request({{"command", "apply_module"}, {"module", module}});
    return requireSuccessfulResponse(applyResponse, "apply_module", error);
}
