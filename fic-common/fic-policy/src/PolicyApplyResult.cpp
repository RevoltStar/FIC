#include <fic/policy/PolicyApplyResult.h>

#include <algorithm>

std::string policyApplyStatusToString(PolicyApplyStatus status) {
    switch (status) {
        case PolicyApplyStatus::Applied:
            return "applied";
        case PolicyApplyStatus::Failed:
            return "failed";
        case PolicyApplyStatus::Disabled:
            return "disabled";
        case PolicyApplyStatus::NotFound:
            return "not_found";
    }
    return "unknown";
}

bool PolicyApplyResult::isApplied() const {
    return status == PolicyApplyStatus::Applied;
}

bool PolicyApplyResult::isFailure() const {
    return status == PolicyApplyStatus::Failed || status == PolicyApplyStatus::NotFound;
}

bool PolicyApplyResult::isDisabled() const {
    return status == PolicyApplyStatus::Disabled;
}

void PolicyApplySummary::add(const PolicyApplyResult& result) {
    results.push_back(result);
}

void PolicyApplySummary::markRequestedRoot(const PolicyRef& policy) {
    requestedRoots_.insert(policy);
}

const std::vector<PolicyApplyResult>& PolicyApplySummary::getResults() const {
    return results;
}

const std::set<PolicyRef>& PolicyApplySummary::requestedRoots() const {
    return requestedRoots_;
}

bool PolicyApplySummary::isRequestedRoot(const PolicyRef& policy) const {
    return requestedRoots_.find(policy) != requestedRoots_.end();
}

bool PolicyApplySummary::requestedRootsApplied() const {
    return !requestedRoots_.empty() &&
        std::all_of(
            requestedRoots_.begin(), requestedRoots_.end(),
            [&](const PolicyRef& root) {
                const auto result = std::find_if(
                    results.begin(), results.end(),
                    [&](const PolicyApplyResult& candidate) {
                        return PolicyRef{
                            candidate.moduleName,
                            candidate.submoduleName,
                            candidate.policyName
                        } == root;
                    });
                return result != results.end() && result->isApplied();
            });
}

bool PolicyApplySummary::requestedRootsWithoutFailures() const {
    return std::all_of(
            requestedRoots_.begin(), requestedRoots_.end(),
            [&](const PolicyRef& root) {
                const auto result = std::find_if(
                    results.begin(), results.end(),
                    [&](const PolicyApplyResult& candidate) {
                        return PolicyRef{
                            candidate.moduleName,
                            candidate.submoduleName,
                            candidate.policyName
                        } == root;
                    });
                return result != results.end() && !result->isFailure();
            });
}

bool PolicyApplySummary::hasFailures() const {
    return std::any_of(results.begin(), results.end(), [](const PolicyApplyResult& result) {
        return result.isFailure();
    });
}

bool PolicyApplySummary::hasDisabled() const {
    return std::any_of(results.begin(), results.end(), [](const PolicyApplyResult& result) {
        return result.isDisabled();
    });
}

bool PolicyApplySummary::hasApplied() const {
    return std::any_of(results.begin(), results.end(), [](const PolicyApplyResult& result) {
        return result.isApplied();
    });
}

std::size_t PolicyApplySummary::totalCount() const {
    return results.size();
}

std::size_t PolicyApplySummary::appliedCount() const {
    return static_cast<std::size_t>(std::count_if(results.begin(), results.end(), [](const PolicyApplyResult& result) {
        return result.status == PolicyApplyStatus::Applied;
    }));
}

std::size_t PolicyApplySummary::failedCount() const {
    return static_cast<std::size_t>(std::count_if(results.begin(), results.end(), [](const PolicyApplyResult& result) {
        return result.status == PolicyApplyStatus::Failed;
    }));
}

std::size_t PolicyApplySummary::disabledCount() const {
    return static_cast<std::size_t>(std::count_if(results.begin(), results.end(), [](const PolicyApplyResult& result) {
        return result.status == PolicyApplyStatus::Disabled;
    }));
}

std::size_t PolicyApplySummary::notFoundCount() const {
    return static_cast<std::size_t>(std::count_if(results.begin(), results.end(), [](const PolicyApplyResult& result) {
        return result.status == PolicyApplyStatus::NotFound;
    }));
}
