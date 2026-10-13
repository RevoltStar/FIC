#include <fic/policy/PolicyDependency.h>
#include <utility>

PolicyDependencyCondition whenBackendRequiresCapability(std::string capability) {
    return {PolicyDependencyConditionType::BackendRequiresCapability, std::move(capability)};
}

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
