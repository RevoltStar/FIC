#ifndef FIC_POLICY_EXECUTION_PLANNER_H
#define FIC_POLICY_EXECUTION_PLANNER_H

#include "policy/registry/PolicyRegistry.h"

#include <fic/policy/PolicyApplyResult.h>

#include <functional>
#include <optional>
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
    // Override only own execution; dependencies, disabled guards and caching
    // remain identical to ordinary apply. nullopt selects ordinary apply().
    using OwnExecutor = std::function<std::optional<PolicyApplyResult>(const PolicyRef&, Policy&)>;
    explicit PolicyExecutionPlanner(PolicyRegistry& registry, OwnExecutor executor = {});

    PolicyApplySummary execute(const PolicyExecutionRequest& request);

private:
    PolicyRegistry& registry_;
    OwnExecutor ownExecutor_;
    std::set<std::string> excludedModules_;
    std::map<PolicyRef, PolicyApplyResult> results_;
    std::set<PolicyRef> visiting_;

    const PolicyApplyResult& executePolicy(
        const PolicyRef& policy,
        PolicyApplySummary& summary);
};

#endif // FIC_POLICY_EXECUTION_PLANNER_H
