#include "core/PolicyExecutionPlanner.h"

#include <fic/core/Logger.h>
#include <fic/policy/PolicyDependencyConditionEvaluator.h>

#include <algorithm>
#include <exception>
#include <iterator>
#include <utility>

namespace {

PolicyDiagnostic dependencyDiagnostic(
    const PolicyRef& dependency,
    PolicyDependencyStrength strength,
    const std::string& detail) {
    const bool required = strength == PolicyDependencyStrength::Required;
    return {
        Logger::get_current_time(),
        Logger::level_to_string(required ? logLevel::ERROR : logLevel::WARN),
        "daemon",
        std::string(required ? "Required" : "Recommended") +
            " dependency was not applied: " + formatPolicyRef(dependency) +
            "; " + detail
    };
}

PolicyApplyResult executeOwnPolicy(
    const PolicyRef& ref,
    Policy& policy) {
    Logger::ScopedCapture capture;
    bool applied = false;
    std::string exceptionMessage;
    try {
        applied = policy.apply();
    } catch (const std::exception& exception) {
        exceptionMessage = "Исключение при применении политики: " +
            std::string(exception.what());
    } catch (...) {
        exceptionMessage = "Неизвестное исключение при применении политики";
    }

    LogCaptureResult captured = capture.finish();
    std::vector<PolicyDiagnostic> diagnostics;
    diagnostics.reserve(
        captured.records.size() + (exceptionMessage.empty() ? 0 : 1));
    for (LogRecord& record : captured.records) {
        diagnostics.push_back({
            std::move(record.timestamp),
            Logger::level_to_string(record.level),
            std::move(record.type),
            std::move(record.message)
        });
    }
    if (!exceptionMessage.empty()) {
        diagnostics.push_back({
            Logger::get_current_time(),
            Logger::level_to_string(logLevel::ERROR),
            "daemon",
            exceptionMessage
        });
    }

    return {
        ref.moduleName,
        ref.submoduleName,
        ref.policyName,
        applied && exceptionMessage.empty()
            ? PolicyApplyStatus::Applied
            : PolicyApplyStatus::Failed,
        exceptionMessage.empty()
            ? (applied ? "Политика успешно применена"
                       : "Не удалось применить политику")
            : exceptionMessage,
        std::move(diagnostics),
        captured.truncated
    };
}

} // namespace

PolicyExecutionPlanner::PolicyExecutionPlanner(PolicyRegistry& registry)
    : registry_(registry) {
}

PolicyApplySummary PolicyExecutionPlanner::execute(
    const PolicyExecutionRequest& request) {
    PolicyApplySummary summary;
    excludedModules_ = request.excludedModules;
    results_.clear();
    visiting_.clear();

    std::set<PolicyRef> roots(
        request.requestedRoots.begin(), request.requestedRoots.end());
    for (const PolicyRef& root : roots) {
        summary.markRequestedRoot(root);
    }
    for (const PolicyRef& root : roots) {
        executePolicy(root, summary);
    }
    return summary;
}

const PolicyApplyResult& PolicyExecutionPlanner::executePolicy(
    const PolicyRef& ref,
    PolicyApplySummary& summary) {
    const auto cached = results_.find(ref);
    if (cached != results_.end()) {
        return cached->second;
    }

    Policy* policy = registry_.findPolicy(ref);
    if (policy == nullptr) {
        PolicyApplyResult result{
            ref.moduleName,
            ref.submoduleName,
            ref.policyName,
            PolicyApplyStatus::NotFound,
            "Политика не существует"
        };
        const auto inserted = results_.emplace(ref, std::move(result));
        summary.add(inserted.first->second);
        return inserted.first->second;
    }

    if (!policy->isEnabled()) {
        PolicyApplyResult result{
            ref.moduleName,
            ref.submoduleName,
            ref.policyName,
            PolicyApplyStatus::Disabled,
            "Политика отключена. Применение не будет выполнено."
        };
        const auto inserted = results_.emplace(ref, std::move(result));
        summary.add(inserted.first->second);
        return inserted.first->second;
    }

    if (!visiting_.insert(ref).second) {
        PolicyApplyResult result{
            ref.moduleName,
            ref.submoduleName,
            ref.policyName,
            PolicyApplyStatus::Failed,
            "Policy dependency cycle reached during execution",
            {{
                Logger::get_current_time(),
                Logger::level_to_string(logLevel::ERROR),
                "daemon",
                "Policy dependency cycle reached during execution at " +
                    formatPolicyRef(ref)
            }}
        };
        const auto inserted = results_.emplace(ref, std::move(result));
        summary.add(inserted.first->second);
        return inserted.first->second;
    }

    std::vector<PolicyDependency> dependencies = policy->dependencies();
    std::sort(
        dependencies.begin(), dependencies.end(),
        [](const PolicyDependency& left, const PolicyDependency& right) {
            return left.policy < right.policy;
        });

    bool requiredBlocked = false;
    std::vector<PolicyDiagnostic> dependencyDiagnostics;
    for (const PolicyDependency& dependency : dependencies) {
        if (!dependencyConditionMatches(*policy, dependency.condition)) {
            continue;
        }
        if (excludedModules_.find(dependency.policy.moduleName) !=
            excludedModules_.end()) {
            dependencyDiagnostics.push_back(dependencyDiagnostic(
                dependency.policy,
                dependency.strength,
                "dependency belongs to explicitly excluded module " +
                    dependency.policy.moduleName));
            requiredBlocked = requiredBlocked ||
                dependency.strength == PolicyDependencyStrength::Required;
            continue;
        }

        const PolicyApplyResult& dependencyResult =
            executePolicy(dependency.policy, summary);
        if (dependencyResult.status != PolicyApplyStatus::Applied) {
            dependencyDiagnostics.push_back(dependencyDiagnostic(
                dependency.policy,
                dependency.strength,
                "dependency status=" +
                    policyApplyStatusToString(dependencyResult.status)));
            requiredBlocked = requiredBlocked ||
                dependency.strength == PolicyDependencyStrength::Required;
        }
    }
    visiting_.erase(ref);

    PolicyApplyResult result;
    if (requiredBlocked) {
        result = {
            ref.moduleName,
            ref.submoduleName,
            ref.policyName,
            PolicyApplyStatus::Failed,
            "Required dependency was not applied",
            std::move(dependencyDiagnostics)
        };
    } else {
        result = executeOwnPolicy(ref, *policy);
        result.diagnostics.insert(
            result.diagnostics.begin(),
            std::make_move_iterator(dependencyDiagnostics.begin()),
            std::make_move_iterator(dependencyDiagnostics.end()));
    }

    const auto inserted = results_.emplace(ref, std::move(result));
    summary.add(inserted.first->second);
    return inserted.first->second;
}
