#include <fic/policy/PolicyDependencyConditionEvaluator.h>

#include <fic/policy/Policy.h>

bool dependencyConditionMatches(
    Policy& owner,
    const PolicyDependencyCondition& condition) {
    switch (condition.type) {
    case PolicyDependencyConditionType::Always:
        return true;
    case PolicyDependencyConditionType::OwnerValueEquals: {
        const std::optional<std::string> ownerValue = owner.getValue();
        return ownerValue.has_value() && *ownerValue == condition.value;
    }
    }
    return false;
}

bool validateDependencyCondition(
    Policy& owner,
    const PolicyDependencyCondition& condition,
    std::string& error) {
    switch (condition.type) {
    case PolicyDependencyConditionType::Always:
        if (!condition.value.empty()) {
            error = "Always dependency condition must not contain a value";
            return false;
        }
        return true;
    case PolicyDependencyConditionType::OwnerValueEquals:
        if (!owner.validate(condition.value)) {
            error = "OwnerValueEquals dependency condition contains an invalid "
                "owner policy value: " + condition.value;
            return false;
        }
        return true;
    }
    error = "unsupported policy dependency condition type";
    return false;
}
