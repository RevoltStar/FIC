#ifndef FIC_POLICY_EXECUTION_PLANNER_H
#define FIC_POLICY_EXECUTION_PLANNER_H

#include "core/PolicyRegistry.h"

#include <fic/policy/PolicyApplyResult.h>

#include <map>
#include <set>
#include <string>
#include <vector>

struct PolicyExecutionRequest {
    std::vector<PolicyRef> requestedRoots;
    std::set<std::string> excludedModules;
};

class PolicyExecutionPlanner {
public:
    explicit PolicyExecutionPlanner(PolicyRegistry& registry);

    PolicyApplySummary execute(const PolicyExecutionRequest& request);

private:
    PolicyRegistry& registry_;
    std::set<std::string> excludedModules_;
    std::map<PolicyRef, PolicyApplyResult> results_;
    std::set<PolicyRef> visiting_;

    const PolicyApplyResult& executePolicy(
        const PolicyRef& policy,
        PolicyApplySummary& summary);
};

#endif // FIC_POLICY_EXECUTION_PLANNER_H
