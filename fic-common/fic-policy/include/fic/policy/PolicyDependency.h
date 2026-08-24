#ifndef FIC_POLICY_DEPENDENCY_H
#define FIC_POLICY_DEPENDENCY_H

#include <string>
#include <tuple>

struct PolicyRef {
    std::string moduleName;
    std::string submoduleName;
    std::string policyName;

    bool operator==(const PolicyRef& other) const {
        return std::tie(moduleName, submoduleName, policyName) ==
            std::tie(other.moduleName, other.submoduleName, other.policyName);
    }

    bool operator!=(const PolicyRef& other) const {
        return !(*this == other);
    }

    bool operator<(const PolicyRef& other) const {
        return std::tie(moduleName, submoduleName, policyName) <
            std::tie(other.moduleName, other.submoduleName, other.policyName);
    }
};

enum class PolicyDependencyStrength {
    Required,
    Recommended
};

enum class PolicyDependencyConditionType {
    Always,
    OwnerValueEquals
};

struct PolicyDependencyCondition {
    PolicyDependencyConditionType type =
        PolicyDependencyConditionType::Always;
    std::string value;
};

struct PolicyDependency {
    PolicyRef policy;
    PolicyDependencyStrength strength = PolicyDependencyStrength::Required;
    PolicyDependencyCondition condition;
};

PolicyDependencyCondition whenOwnerValueEquals(std::string value);
std::string formatPolicyRef(const PolicyRef& policy);

#endif // FIC_POLICY_DEPENDENCY_H
