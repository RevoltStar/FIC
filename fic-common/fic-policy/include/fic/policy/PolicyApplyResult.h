#ifndef POLICY_APPLY_RESULT_H
#define POLICY_APPLY_RESULT_H

#include <cstddef>
#include <set>
#include <string>
#include <vector>

#include <fic/policy/PolicyDependency.h>

enum class PolicyApplyStatus {
    Applied,
    Failed,
    Disabled,
    NotFound
};

std::string policyApplyStatusToString(PolicyApplyStatus status);

struct PolicyDiagnostic {
    std::string timestamp;
    std::string level;
    std::string category;
    std::string message;
};

struct PolicyApplyResult {
    std::string moduleName;
    std::string submoduleName;
    std::string policyName;
    PolicyApplyStatus status;
    std::string message;
    std::vector<PolicyDiagnostic> diagnostics;
    bool diagnosticsTruncated = false;

    bool isApplied() const;
    bool isFailure() const;
    bool isDisabled() const;
};

class PolicyApplySummary {
public:
    void add(const PolicyApplyResult& result);
    void markRequestedRoot(const PolicyRef& policy);

    const std::vector<PolicyApplyResult>& getResults() const;
    const std::set<PolicyRef>& requestedRoots() const;
    bool isRequestedRoot(const PolicyRef& policy) const;
    bool requestedRootsApplied() const;
    bool requestedRootsWithoutFailures() const;
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
    std::set<PolicyRef> requestedRoots_;
};

#endif // POLICY_APPLY_RESULT_H
