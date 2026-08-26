#include "policy/execution/PolicyApplication.h"

#include "policy/execution/PolicyExecutionPlanner.h"

PolicyApplySummary applyPolicy(
    PolicyRegistry& policyRegistry,
    std::string module,
    std::string policy) {
    PolicyExecutionRequest request;
    const auto moduleIt = policyRegistry.find(module);
    if (moduleIt == policyRegistry.end()) {
        PolicyApplySummary summary;
        summary.markRequestedRoot({module, "", policy});
        summary.add({
            module, "", policy, PolicyApplyStatus::NotFound,
            "Модуль не существует"
        });
        return summary;
    }

    for (const auto& [submoduleName, submodulePolicies] :
         moduleIt->second.submodules) {
        if (submodulePolicies.find(policy) == submodulePolicies.end()) {
            continue;
        }
        request.requestedRoots.push_back({module, submoduleName, policy});
        return PolicyExecutionPlanner(policyRegistry).execute(request);
    }

    PolicyApplySummary summary;
    summary.markRequestedRoot({module, "", policy});
    summary.add({
        module, "", policy, PolicyApplyStatus::NotFound,
        "Политика не существует"
    });
    return summary;
}

PolicyApplySummary applyModulePolicies(
    PolicyRegistry& policyRegistry,
    std::string module) {
    PolicyExecutionRequest request;
    const auto moduleIt = policyRegistry.find(module);
    if (moduleIt == policyRegistry.end()) {
        PolicyApplySummary summary;
        summary.markRequestedRoot({module, "", "all"});
        summary.add({
            module, "", "all", PolicyApplyStatus::NotFound,
            "Модуль не существует"
        });
        return summary;
    }

    for (const auto& [submoduleName, submodulePolicies] :
         moduleIt->second.submodules) {
        for (const auto& [policyName, policyClass] : submodulePolicies) {
            (void)policyClass;
            request.requestedRoots.push_back(
                {module, submoduleName, policyName});
        }
    }
    return PolicyExecutionPlanner(policyRegistry).execute(request);
}

PolicyApplySummary applyAllPolicies(PolicyRegistry& policyRegistry) {
    PolicyExecutionRequest request;
    for (const auto& [moduleName, policyModule] : policyRegistry) {
        for (const auto& [submoduleName, submodulePolicies] :
             policyModule.submodules) {
            for (const auto& [policyName, policyClass] : submodulePolicies) {
                (void)policyClass;
                request.requestedRoots.push_back(
                    {moduleName, submoduleName, policyName});
            }
        }
    }
    return PolicyExecutionPlanner(policyRegistry).execute(request);
}

PolicyApplySummary applyAllPoliciesExceptModule(
    PolicyRegistry& policyRegistry,
    const std::string& excludedModule) {
    PolicyExecutionRequest request;
    request.excludedModules.insert(excludedModule);
    for (const auto& [moduleName, policyModule] : policyRegistry) {
        if (moduleName == excludedModule) {
            continue;
        }
        for (const auto& [submoduleName, submodulePolicies] :
             policyModule.submodules) {
            for (const auto& [policyName, policyClass] : submodulePolicies) {
                (void)policyClass;
                request.requestedRoots.push_back(
                    {moduleName, submoduleName, policyName});
            }
        }
    }
    return PolicyExecutionPlanner(policyRegistry).execute(request);
}

bool isPolicyApplySuccessful(
    const PolicyApplySummary& summary,
    const std::string& module,
    const std::string& policy) {
    const bool isSinglePolicyRequest = module != "all" && policy != "all";
    return isSinglePolicyRequest
        ? summary.requestedRootsApplied()
        : summary.requestedRootsWithoutFailures();
}
