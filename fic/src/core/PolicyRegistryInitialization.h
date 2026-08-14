#ifndef POLICY_REGISTRY_INITIALIZATION_H
#define POLICY_REGISTRY_INITIALIZATION_H

#include <exception>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "core/PolicyRegistry.h"

using PolicyList = std::vector<std::unique_ptr<Policy>>;

bool buildPolicyRegistry(
    PolicyList policies,
    PolicyRegistry& registry,
    std::string& error);

template<typename PolicyFactory>
bool rebuildPolicyRegistry(
    PolicyFactory&& policyFactory,
    PolicyRegistry& registry,
    std::string& error)
{
    try {
        return buildPolicyRegistry(
            std::forward<PolicyFactory>(policyFactory)(), registry, error);
    } catch (const std::exception& exception) {
        error = "PolicyRegistry policy creation failed: " +
            std::string(exception.what());
        return false;
    } catch (...) {
        error = "PolicyRegistry policy creation failed: unknown exception";
        return false;
    }
}

#endif // POLICY_REGISTRY_INITIALIZATION_H
