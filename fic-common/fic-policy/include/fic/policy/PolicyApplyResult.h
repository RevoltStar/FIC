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

// WHY a policy result is Failed.
//
// Diagnostic only: FailureOrigin NEVER suppresses or gates incident
// activation. An enabled policy that ends in PolicyApplyStatus::Failed always
// activates that policy's OWN violation_severity, regardless of how it failed.
// The origin exists so the audit trail can explain the failure without the
// security decision having to branch on it.
enum class PolicyFailureOrigin {
    // Status is not Failed.
    None,
    // The policy's own Policy::apply() returned false or threw.
    OwnApplyFailure,
    // The policy's apply() was never invoked because a REQUIRED dependency did
    // not reach PolicyApplyStatus::Applied. The dependent policy itself is
    // still Failed and still raises its own severity - this is NOT severity
    // inheritance.
    RequiredDependencyBlocked,
    // A dependency cycle was reached while executing this policy.
    DependencyCycle,
    // The execution infrastructure could not evaluate or run the policy.
    ExecutionInfrastructureFailure
};

std::string policyFailureOriginToString(PolicyFailureOrigin origin);

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

    // Present only when status == Failed.
    PolicyFailureOrigin failureOrigin = PolicyFailureOrigin::None;
    // True only when this policy's own apply() was actually invoked. A
    // policy blocked by a Required dependency has ownApplyAttempted == false
    // and still counts as Failed for incident activation purposes.
    bool ownApplyAttempted = false;

    bool isApplied() const;
    bool isFailure() const;
    bool isDisabled() const;

    // The invariant the incident layer depends on: enabled + Failed, whatever
    // the origin. There is deliberately no origin-based suppression here.
    bool activatesIncident() const {
        return status == PolicyApplyStatus::Failed;
    }
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
