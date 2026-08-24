#ifndef FIC_POLICY_DEPENDENCY_CONDITION_EVALUATOR_H
#define FIC_POLICY_DEPENDENCY_CONDITION_EVALUATOR_H

#include <fic/policy/PolicyDependency.h>

#include <string>

class Policy;

bool dependencyConditionMatches(
    Policy& owner,
    const PolicyDependencyCondition& condition);

bool validateDependencyCondition(
    Policy& owner,
    const PolicyDependencyCondition& condition,
    std::string& error);

#endif // FIC_POLICY_DEPENDENCY_CONDITION_EVALUATOR_H
