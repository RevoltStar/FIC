#include <fic/policy/PolicyDependency.h>

#include <utility>

PolicyDependencyCondition whenOwnerValueEquals(std::string value) {
    return {
        PolicyDependencyConditionType::OwnerValueEquals,
        std::move(value)
    };
}

std::string formatPolicyRef(const PolicyRef& policy) {
    return policy.moduleName + ":" + policy.submoduleName + ":" +
        policy.policyName;
}
