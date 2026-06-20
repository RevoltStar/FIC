#ifndef POLICY_APPLY_RESULT_H
#define POLICY_APPLY_RESULT_H

#include <cstddef>
#include <string>
#include <vector>

enum class PolicyApplyStatus {
    Applied,
    Failed,
    Disabled,
    NotFound
};

std::string policyApplyStatusToString(PolicyApplyStatus status);

struct PolicyApplyResult {
    std::string moduleName;
    std::string submoduleName;
    std::string policyName;
    PolicyApplyStatus status;
    std::string message;

    bool isApplied() const;
    bool isFailure() const;
    bool isDisabled() const;
};

class PolicyApplySummary {
public:
    void add(const PolicyApplyResult& result);

    const std::vector<PolicyApplyResult>& getResults() const;
    bool hasFailures() const;
    bool hasDisabled() const;
    bool hasApplied() const;

    std::size_t totalCount() const;
    std::size_t appliedCount() const;
    std::size_t failedCount() const;
    std::size_t disabledCount() const;
    std::size_t notFoundCount() const;

private:
    std::vector<PolicyApplyResult> results;
};

#endif // POLICY_APPLY_RESULT_H
