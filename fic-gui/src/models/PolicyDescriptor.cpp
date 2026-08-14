#include "models/PolicyDescriptor.h"

#include <nlohmann/json.hpp>

bool parsePolicyDescriptors(
    const nlohmann::json& response,
    const std::string& expectedModule,
    std::vector<PolicyDescriptor>& policies,
    std::string& error)
{
    policies.clear();
    error.clear();
    if (!response.value("ok", false)) {
        error = response.value("message", "failed to load policies");
        return false;
    }
    if (!response.contains("policies") || !response["policies"].is_array()) {
        error = "daemon response does not contain a policies array";
        return false;
    }

    for (const auto& item : response["policies"]) {
        if (!item.is_object()) {
            error = "invalid policy descriptor";
            policies.clear();
            return false;
        }
        PolicyDescriptor policy;
        policy.moduleName = item.value("module", "");
        policy.submoduleName = item.value("submodule", "");
        policy.policyName = item.value("policy", "");
        policy.editor = item.value("editor", "unknown");
        policy.value = item.value("value", item.value("default_value", ""));
        policy.defaultValue = item.value("default_value", "");
        policy.textDelimiter = item.value("text_delimiter", "");
        policy.restriction = item.value("restriction", "");
        policy.enabled = item.value("enabled", false);
        policy.isSet = item.value("set", false);
        policy.valueValid = item.value("value_valid", true);
        policy.min = item.value("min", 0);
        policy.max = item.value("max", 0);
        if (policy.moduleName != expectedModule || policy.policyName.empty()) {
            error = "policy descriptor does not match requested module";
            policies.clear();
            return false;
        }
        if (item.contains("possible_values") && item["possible_values"].is_array()) {
            for (const auto& value : item["possible_values"]) {
                if (value.is_string()) {
                    policy.possibleValues.push_back(value.get<std::string>());
                }
            }
        }
        policies.push_back(std::move(policy));
    }
    return true;
}
