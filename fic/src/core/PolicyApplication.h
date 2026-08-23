#ifndef FIC_POLICY_APPLICATION_H
#define FIC_POLICY_APPLICATION_H

#include "core/PolicyRegistry.h"

#include <fic/policy/PolicyApplyResult.h>

#include <string>

PolicyApplySummary applyPolicy(
    PolicyRegistry& policyRegistry,
    std::string module,
    std::string policy);
PolicyApplySummary applyModulePolicies(
    PolicyRegistry& policyRegistry,
    std::string module);
PolicyApplySummary applyAllPolicies(PolicyRegistry& policyRegistry);
PolicyApplySummary applyAllPoliciesExceptModule(
    PolicyRegistry& policyRegistry,
    const std::string& excludedModule);
bool isPolicyApplySuccessful(
    const PolicyApplySummary& summary,
    const std::string& module,
    const std::string& policy);

#endif // FIC_POLICY_APPLICATION_H
