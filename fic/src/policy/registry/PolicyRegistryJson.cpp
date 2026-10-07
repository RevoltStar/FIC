#include "policy/registry/PolicyRegistryJson.h"

#include <fic/core/incident/IncidentSeverity.h>
#include <fic/policy/PolicyDependencyConditionEvaluator.h>

using ::fic::core::violationSeverityToken;

#include <nlohmann/json.hpp>

nlohmann::json moduleDescriptorsJson(const PolicyRegistry& registry)
{
    nlohmann::json modules = nlohmann::json::array();
    for (const auto& [name, module] : registry) {
        modules.push_back({
            {"name", name},
            {"view", moduleViewName(module.view)},
            {"display_order", module.displayOrder}
        });
    }
    return modules;
}

nlohmann::json policyToJson(const std::string& module,
                            const std::string& submodule,
                            const std::string& policy,
                            Policy& policyClass)
{
    const PolicyTypeValue& typeValue = policyClass.getPolicyTypeValue();
    const PolicyEditorSpec editorSpec = typeValue.getEditorSpec();
    const bool isSet = policyClass.hasConfiguredValue();
    bool valueValid = true;
    std::string value = policyClass.getDefaultValue();

    if (isSet) {
        try {
            const std::optional<std::string> currentValue = policyClass.getValue();
            if (currentValue.has_value()) {
                value = *currentValue;
            } else {
                valueValid = false;
            }
        } catch (const std::exception&) {
            valueValid = false;
        }
    }

    nlohmann::json possibleValues = nlohmann::json::array();
    for (const std::string& possibleValue : editorSpec.possibleValues) {
        possibleValues.push_back(possibleValue);
    }

    nlohmann::json item = {
        {"module", module},
        {"submodule", submodule},
        {"policy", policy},
        {"enabled", policyClass.isEnabled()},
        {"set", isSet},
        {"value", value},
        {"value_valid", valueValid},
        {"default_value", policyClass.getDefaultValue()},
        {"editor", editorSpec.editor},
        {"validator", editorSpec.validator},
        {"possible_values", possibleValues},
        {"restriction", policyClass.getPolicyRestriction()},
        // Incident metadata. The effective severity is what the daemon
        // activates when THIS policy ends in Failed; it is never inherited
        // along the dependency graph.
        {"violation_severity",
         violationSeverityToken(policyClass.getViolationSeverity())},
        {"default_violation_severity",
         violationSeverityToken(policyClass.getDefaultViolationSeverity())}
    };

    // The full set a client may choose, so an editor never has to invent one.
    nlohmann::json violationSeverities = nlohmann::json::array();
    for (const ::fic::core::ViolationSeverity severity :
         {::fic::core::ViolationSeverity::None,
          ::fic::core::ViolationSeverity::Soft,
          ::fic::core::ViolationSeverity::Standard,
          ::fic::core::ViolationSeverity::Hard,
          ::fic::core::ViolationSeverity::Isolate}) {
        violationSeverities.push_back(violationSeverityToken(severity));
    }
    item["violation_severity_values"] = std::move(violationSeverities);

    nlohmann::json required = nlohmann::json::array();
    if (policyClass.isEnabled()) {
        for (const auto& dependency : policyClass.dependencies()) {
            if (dependency.strength == PolicyDependencyStrength::Required &&
                dependencyConditionMatches(policyClass, dependency.condition)) {
                required.push_back({
                    {"module", dependency.policy.moduleName},
                    {"submodule", dependency.policy.submoduleName},
                    {"policy", dependency.policy.policyName}
                });
            }
        }
    }
    item["required_dependencies"] = std::move(required);

    if (editorSpec.min.has_value()) {
        item["min"] = *editorSpec.min;
    }
    if (editorSpec.max.has_value()) {
        item["max"] = *editorSpec.max;
    }
    if (editorSpec.textDelimiter.has_value()) {
        item["text_delimiter"] = *editorSpec.textDelimiter;
    }
    return item;
}

nlohmann::json policyListJson(const PolicyRegistry& registry,
                              const std::string& module)
{
    nlohmann::json result = nlohmann::json::array();
    const auto moduleIt = registry.find(module);
    if (moduleIt == registry.end()) {
        return result;
    }

    for (const auto& [submodule, policies] : moduleIt->second.submodules) {
        for (const auto& [policy, policyClass] : policies) {
            result.push_back(policyToJson(
                module, submodule, policy, *policyClass));
        }
    }
    return result;
}
