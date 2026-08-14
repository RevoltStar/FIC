#include "services/PolicyService.h"

#include <nlohmann/json.hpp>

#include <fic/ipc/FicIpcClient.h>

bool PolicyService::loadModules(
    std::vector<ModuleDescriptor>& modules,
    QString& error) const
{
    const auto response = fic::ipc::Client().request({{"command", "module_list"}});
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
    const auto response = fic::ipc::Client().request({
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
    fic::ipc::Client client;
    for (const PolicyChange& change : changes) {
        if (change.valueConfigurable) {
            const auto response = client.request({
                {"command", "set_policy_value"},
                {"module", module},
                {"policy", change.policyName},
                {"value", change.value}
            });
            if (!response.value("ok", false)) {
                error = QString::fromStdString(response.value("message", "failed to set policy value"));
                return false;
            }
        }
        const auto response = client.request({
            {"command", change.enabled ? "enable_policy" : "disable_policy"},
            {"module", module},
            {"policy", change.policyName}
        });
        if (!response.value("ok", false)) {
            error = QString::fromStdString(response.value("message", "failed to change policy state"));
            return false;
        }
    }
    applyResponse = client.request({{"command", "apply_module"}, {"module", module}});
    return true;
}
