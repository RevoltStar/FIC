#include <fic/policy/PolicyDependency.h>

std::string formatPolicyRef(const PolicyRef& policy) {
    return policy.moduleName + ":" + policy.submoduleName + ":" +
        policy.policyName;
}
