#include "features/policies/services/PolicyService.h"

#include <algorithm>
#include <map>
#include <set>
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

// Nodes are ordered by phase, then by the original row order. Kahn's
// algorithm keeps that order whenever dependency constraints allow it.
bool planSave(const std::string& module,
              const std::vector<PolicyChange>& changes,
              const std::vector<PolicyDescriptor>& policies,
              std::vector<nlohmann::json>& plan,
              QString& error)
{
    std::vector<nlohmann::json> operations;
    std::map<std::pair<std::size_t, std::string>, std::size_t> nodes;
    const auto add = [&](std::size_t i, const std::string& command,
                         nlohmann::json fields = nlohmann::json::object()) {
        fields["command"] = command;
        fields["module"] = module;
        fields["policy"] = changes[i].policyName;
        nodes[{i, command}] = operations.size();
        operations.push_back(std::move(fields));
    };
    std::map<std::string, std::size_t> changed;
    std::vector<const PolicyDescriptor*> descriptors;
    for (std::size_t i = 0; i < changes.size(); ++i) {
        const auto& change = changes[i];
        auto descriptor = std::find_if(policies.begin(), policies.end(),
            [&](const auto& p) { return p.policyName == change.policyName; });
        if (descriptor == policies.end() ||
            !changed.emplace(change.policyName, i).second) {
            error = "Cannot plan save: unknown or duplicate policy " +
                QString::fromStdString(change.policyName);
            return false;
        }
        descriptors.push_back(&*descriptor);
        if (change.enabledChanged && !change.enabled) add(i, "disable_policy");
    }
    for (std::size_t i = 0; i < changes.size(); ++i) {
        const auto& change = changes[i];
        if (change.violationSeverityChanged)
            add(i, "set_policy_violation_severity",
                {{"violation_severity", change.violationSeverity}});
        if (change.valueConfigurable && change.valueChanged)
            add(i, "set_policy_value", {{"value", change.value}});
    }
    for (std::size_t i = 0; i < changes.size(); ++i)
        if (changes[i].enabledChanged && changes[i].enabled) add(i, "enable_policy");

    std::vector<std::set<std::size_t>> edges(operations.size());
    std::vector<std::pair<std::size_t, std::size_t>> preferences;
    const auto constrain = [&](std::size_t from, const char* fromCommand,
                               std::size_t to, const char* toCommand,
                               bool recommended = false) {
        const auto a = nodes.find({from, fromCommand});
        const auto b = nodes.find({to, toCommand});
        if (a == nodes.end() || b == nodes.end()) return;
        if (recommended) preferences.emplace_back(a->second, b->second);
        else edges[a->second].insert(b->second);
    };
    for (std::size_t i = 0; i < changes.size(); ++i) {
        constrain(i, "disable_policy", i, "set_policy_value");
        constrain(i, "disable_policy", i, "set_policy_violation_severity");
        constrain(i, "set_policy_value", i, "enable_policy");
        constrain(i, "set_policy_violation_severity", i, "enable_policy");
        const auto& owner = *descriptors[i];
        const auto& change = changes[i];
        const bool targetEnabled = change.enabledChanged ? change.enabled : owner.enabled;
        for (const auto& dependency : owner.dependencies) {
            const auto found = changed.find(dependency.policyName);
            if (dependency.moduleName != module || found == changed.end()) continue;
            const auto j = found->second;
            if (dependency.submoduleName != descriptors[j]->submoduleName) continue;
            const bool soft = dependency.strength == "recommended";
            const bool targetActive = dependency.condition == "owner_value_equals" &&
                    change.valueConfigurable && change.valueChanged
                ? change.value == dependency.value : dependency.active;
            if (owner.enabled && dependency.active) {
                constrain(i, "disable_policy", j, "disable_policy", soft);
                constrain(i, "disable_policy", j, "set_policy_value", soft);
                // A still-enabled owner can release a conditional requirement
                // by changing its value, before its dependency is disabled.
                if (targetEnabled && !targetActive)
                    constrain(i, "set_policy_value", j, "disable_policy", soft);
            }
            if (targetEnabled && targetActive) {
                constrain(j, "enable_policy", i, "enable_policy", soft);
                constrain(j, "enable_policy", i, "set_policy_value", soft);
                constrain(j, "set_policy_value", i, "enable_policy", soft);
                constrain(j, "set_policy_value", i, "set_policy_value", soft);
            }
        }
    }
    // Recommendations only choose an order; they never make a save impossible.
    for (const auto& [from, to] : preferences) {
        std::set<std::size_t> visited;
        std::vector<std::size_t> pending{to};
        while (!pending.empty()) {
            const auto node = pending.back();
            pending.pop_back();
            if (!visited.insert(node).second) continue;
            pending.insert(pending.end(), edges[node].begin(), edges[node].end());
        }
        if (!visited.count(from)) edges[from].insert(to);
    }
    std::vector<std::size_t> indegree(operations.size());
    for (const auto& successors : edges)
        for (const auto successor : successors) ++indegree[successor];
    std::set<std::size_t> ready;
    for (std::size_t i = 0; i < operations.size(); ++i)
        if (!indegree[i]) ready.insert(i);
    while (!ready.empty()) {
        const auto node = *ready.begin();
        ready.erase(ready.begin());
        plan.push_back(operations[node]);
        for (const auto successor : edges[node])
            if (!--indegree[successor]) ready.insert(successor);
    }
    if (plan.size() != operations.size()) {
        error = "Cannot order policy save operations: required dependency cycle";
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
    if (std::none_of(changes.begin(), changes.end(), [](const auto& change) {
            return change.enabledChanged || change.violationSeverityChanged ||
                (change.valueConfigurable && change.valueChanged);
        })) return true;

    // Refresh metadata once before any mutation (including backend conditions).
    std::vector<PolicyDescriptor> policies;
    if (!loadPolicies(module, policies, error)) return false;
    std::vector<nlohmann::json> plan;
    if (!planSave(module, changes, policies, plan, error)) return false;
    for (const auto& operation : plan) {
        nlohmann::json response;
        const std::string command = operation.at("command");
        if (!requireResponseEnvelope(request(operation), command.c_str(), true,
                                     response, error)) {
            error = QString("%1 failed for %2: %3")
                .arg(QString::fromStdString(command),
                     QString::fromStdString(operation.at("policy").get<std::string>()),
                     error);
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
        result.status = ApplyStatus::SaveFailed;
        return result;
    }
    const RequestResult requestResult = request(
        {{"command", "apply_module"}, {"module", module}});
    if (!requireApplyResponse(requestResult, result.response, result.error)) {
        result.response = nlohmann::json();
        result.status = ApplyStatus::ApplyFailed;
        return result;
    }
    result.status = ApplyStatus::Completed;
    return result;
}
