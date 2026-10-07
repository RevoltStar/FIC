#include "policy/execution/PolicyDependencyGraph.h"

#include <fic/policy/PolicyDependencyConditionEvaluator.h>

#include <algorithm>
#include <map>
#include <set>
#include <sstream>
#include <vector>

namespace {

enum class VisitState {
    Visiting,
    Visited
};

bool validPolicyRef(const PolicyRef& policy) {
    return !policy.moduleName.empty() && !policy.submoduleName.empty() &&
        !policy.policyName.empty();
}

bool visitPolicy(
    const PolicyRegistry& registry,
    const PolicyRef& current,
    std::map<PolicyRef, VisitState>& states,
    std::vector<PolicyRef>& path,
    std::string& error) {
    states[current] = VisitState::Visiting;
    path.push_back(current);

    const Policy* policy = registry.findPolicy(current);
    if (policy == nullptr) {
        error = "dependency graph references missing policy " +
            formatPolicyRef(current);
        return false;
    }

    std::vector<PolicyRef> targets;
    targets.reserve(policy->dependencies().size());
    for (const PolicyDependency& dependency : policy->dependencies()) {
        targets.push_back(dependency.policy);
    }
    std::sort(targets.begin(), targets.end());

    for (const PolicyRef& target : targets) {
        const auto state = states.find(target);
        if (state != states.end() && state->second == VisitState::Visiting) {
            const auto cycleStart = std::find(path.begin(), path.end(), target);
            std::ostringstream cycle;
            bool first = true;
            for (auto item = cycleStart; item != path.end(); ++item) {
                if (!first) {
                    cycle << " -> ";
                }
                cycle << formatPolicyRef(*item);
                first = false;
            }
            cycle << " -> " << formatPolicyRef(target);
            error = "policy dependency cycle detected: " + cycle.str();
            return false;
        }
        if (state == states.end() &&
            !visitPolicy(registry, target, states, path, error)) {
            return false;
        }
    }

    path.pop_back();
    states[current] = VisitState::Visited;
    return true;
}

} // namespace

std::vector<PolicyRef> enabledRequiredDependents(
    PolicyRegistry& registry,
    const PolicyRef& dependency) {
    std::vector<PolicyRef> dependents;
    for (const PolicyRef& candidate : registry.policyRefs()) {
        if (candidate == dependency) {
            continue;
        }
        Policy* policy = registry.findPolicy(candidate);
        if (policy == nullptr || !policy->isEnabled()) {
            continue;
        }
        bool requires = false;
        for (const PolicyDependency& declared : policy->dependencies()) {
            if (declared.policy == dependency &&
                declared.strength == PolicyDependencyStrength::Required &&
                dependencyConditionMatches(*policy, declared.condition)) {
                requires = true;
                break;
            }
        }
        if (requires) {
            dependents.push_back(candidate);
        }
    }
    // registry.policyRefs() is already deterministic (map order), but keep the
    // contract explicit.
    std::sort(dependents.begin(), dependents.end());
    return dependents;
}

bool validatePolicyDependencyGraph(
    PolicyRegistry& registry,
    std::string& error) {
    error.clear();
    const std::vector<PolicyRef> policies = registry.policyRefs();
    for (const PolicyRef& owner : policies) {
        Policy* policy = registry.findPolicy(owner);
        std::map<PolicyRef, PolicyDependencyStrength> targets;
        for (const PolicyDependency& dependency : policy->dependencies()) {
            if (!validPolicyRef(dependency.policy)) {
                error = "policy " + formatPolicyRef(owner) +
                    " contains an incomplete dependency reference";
                return false;
            }
            if (dependency.policy == owner) {
                error = "policy " + formatPolicyRef(owner) +
                    " depends on itself";
                return false;
            }
            if (registry.findPolicy(dependency.policy) == nullptr) {
                error = "policy " + formatPolicyRef(owner) +
                    " references unknown dependency " +
                    formatPolicyRef(dependency.policy);
                return false;
            }
            std::string conditionError;
            if (!validateDependencyCondition(
                    *policy, dependency.condition, conditionError)) {
                error = "policy " + formatPolicyRef(owner) +
                    " contains invalid dependency condition for " +
                    formatPolicyRef(dependency.policy) + ": " + conditionError;
                return false;
            }
            const auto existing = targets.find(dependency.policy);
            if (existing != targets.end()) {
                error = "policy " + formatPolicyRef(owner) +
                    (existing->second == dependency.strength
                         ? " declares duplicate dependency "
                         : " declares dependency as both Required and Recommended ") +
                    formatPolicyRef(dependency.policy);
                return false;
            }
            targets.emplace(dependency.policy, dependency.strength);
        }
    }

    std::map<PolicyRef, VisitState> states;
    std::vector<PolicyRef> path;
    for (const PolicyRef& policy : policies) {
        if (states.find(policy) == states.end() &&
            !visitPolicy(registry, policy, states, path, error)) {
            return false;
        }
    }
    return true;
}
