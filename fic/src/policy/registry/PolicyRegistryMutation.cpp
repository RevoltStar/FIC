#include "policy/registry/PolicyRegistryMutation.h"

#include <fic/core/config/ModuleConfigFileHandler.h>
#include <fic/core/incident/IncidentSeverity.h>

#include "policy/registry/PolicyRegistryJson.h"

namespace {

Policy* findPolicy(PolicyRegistry& registry,
                   const std::string& module,
                   const std::string& policy)
{
    const auto moduleIt = registry.find(module);
    if (moduleIt == registry.end()) {
        return nullptr;
    }
    for (const auto& [submodule, policies] : moduleIt->second.submodules) {
        (void)submodule;
        const auto found = policies.find(policy);
        if (found != policies.end()) {
            return found->second.get();
        }
    }
    return nullptr;
}

} // namespace

bool setPolicyValue(PolicyRegistry& registry,
                    const std::string& module,
                    const std::string& policy,
                    const std::string& logicalValue,
                    std::string& error)
{
    Policy* const concretePolicy = findPolicy(registry, module, policy);
    if (concretePolicy == nullptr) {
        error = "policy does not exist";
        return false;
    }
    if (!concretePolicy->validate(logicalValue)) {
        error = "policy value is invalid";
        return false;
    }

    const std::string storageValue =
        concretePolicy->postprocessingValue(logicalValue);
    if (storageValue.empty()) {
        error = "policy value serialization failed";
        return false;
    }

    ModuleConfigFileHandler config(module);
    if (!config.loadConfig()) {
        error = "could not load module configuration";
        return false;
    }
    if (!config.setPolicyValue(policy, storageValue)) {
        error = "could not set policy value";
        return false;
    }
    if (!config.saveConfig()) {
        error = "could not save module configuration";
        return false;
    }
    error.clear();
    return true;
}

bool setPolicyViolationSeverity(PolicyRegistry& registry,
                                const std::string& module,
                                const std::string& policy,
                                const std::string& severityToken,
                                std::string& error)
{
    Policy* const concretePolicy = findPolicy(registry, module, policy);
    if (concretePolicy == nullptr) {
        error = "policy does not exist";
        return false;
    }

    const auto severity = ::fic::core::parseViolationSeverityToken(severityToken);
    if (!severity.has_value()) {
        error = "unknown violation severity: " + severityToken;
        return false;
    }

    ModuleConfigFileHandler config(module);
    if (!config.loadConfig()) {
        error = "could not load module configuration";
        return false;
    }
    if (!config.setPolicyViolationSeverity(policy, *severity)) {
        error = "could not set policy violation severity";
        return false;
    }
    if (!config.saveConfig()) {
        error = "could not save module configuration";
        return false;
    }
    error.clear();
    return true;
}
