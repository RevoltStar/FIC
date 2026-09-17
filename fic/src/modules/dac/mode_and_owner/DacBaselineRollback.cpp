#include "modules/dac/mode_and_owner/DacBaselineRollback.h"

#include "modules/dac/mode_and_owner/policies/DAC_blocking_user_access_to_system_files.h"
#include "rollback/MutationRecord.h"
#include "rollback/RollbackExecutor.h"

#include <fic/core/fs/FileStats.h>

#include <algorithm>
#include <mutex>
#include <string>
#include <vector>

namespace fic::rollback {
namespace {

// Serializes DAC baseline mutations with policy apply.
std::mutex& dacBaselineMutex() {
    static std::mutex mutex;
    return mutex;
}

enum class ResourceOutcome {
    Applied,    // object transitioned to the platform baseline
    Compliant,  // object missing (nothing to restore) or already at baseline
    Conflict,   // fail-closed unsafe object; nothing was mutated
    Failed      // operational failure
};

// Applies exact baseline metadata to an already safely opened object and
// verifies the postcondition via fstat (refresh on the pinned descriptor).
ResourceOutcome transitionToBaseline(
    FileStats& current,
    const fic::platform::FileMetadata& baseline,
    std::string& detail) {
    uid_t ownerId = 0;
    gid_t groupId = 0;
    const FileStatsOperationResult identityResult =
        FileStats::resolve_owner_group(
            baseline.owner, baseline.group, ownerId, groupId);
    if (!identityResult) {
        detail = identityResult.message;
        return ResourceOutcome::Failed;
    }

    bool compliant = true;
    if (current.owner_id() != ownerId || current.group_id() != groupId) {
        compliant = false;
        const FileStatsOperationResult change =
            current.change_owner_group(ownerId, groupId);
        if (!change) {
            detail = change.message;
            return ResourceOutcome::Failed;
        }
    }
    if ((current._permissions & 07777) !=
        (baseline.permissions & 07777)) {
        compliant = false;
        const FileStatsOperationResult change =
            current.change_permissions(baseline.permissions);
        if (!change) {
            detail = change.message;
            return ResourceOutcome::Failed;
        }
    }

    // Postcondition: re-read the object state through the pinned descriptor.
    const FileStatsOperationResult refreshed = current.refresh();
    if (!refreshed ||
        current.owner_id() != ownerId ||
        current.group_id() != groupId ||
        (current._permissions & 07777) != (baseline.permissions & 07777)) {
        detail = refreshed
            ? "baseline postcondition failed"
            : refreshed.message;
        return ResourceOutcome::Failed;
    }
    return compliant ? ResourceOutcome::Compliant
                     : ResourceOutcome::Applied;
}

// One managed resource of a FileAccessRule: safe path resolution identical
// to apply (symlink allowlists + provider target validation), then a strict
// transition of the resolved object to its baseline metadata.
ResourceOutcome rollbackFileAccessRule(
    const fic::platform::FileAccessRule& rule,
    std::string& detail) {
    std::vector<std::filesystem::path> allowedTargets =
        rule.allowedFinalSymlinkTargets;
    for (const auto& target : rule.providerManagedFinalSymlinkTargets) {
        allowedTargets.push_back(target.path);
    }
    FileStats current = FileStats::openPolicyPath(
        rule.path.string(), allowedTargets,
        PolicyPathResolution::Standard);
    if (current.is_missing()) {
        // MissingFilePolicy::Ignore semantics: rollback never creates a
        // system file just to restore its baseline.
        return ResourceOutcome::Compliant;
    }
    if (current.has_error()) {
        // Fail closed: unsafe pathname resolution (symlink substitution
        // outside the allowlist and similar) must abort before mutation.
        detail = "не удалось безопасно открыть объект: " +
                 current.error_message();
        return ResourceOutcome::Conflict;
    }

    const auto providerTarget = std::find_if(
        rule.providerManagedFinalSymlinkTargets.begin(),
        rule.providerManagedFinalSymlinkTargets.end(),
        [&](const auto& target) {
            return target.path == current.opened_policy_path();
        });
    if (providerTarget !=
            rule.providerManagedFinalSymlinkTargets.end()) {
        if (!current.is_regular_file()) {
            detail = "неожиданный тип provider-managed объекта: " +
                     current.opened_policy_path().string();
            return ResourceOutcome::Conflict;
        }
        return transitionToBaseline(current, providerTarget->baseline, detail);
    }

    // Static regular path: the rule baseline is authoritative. The rule
    // describes a regular file: an unexpected object type (directory,
    // device node, ...) must fail closed before any metadata mutation.
    if (!current.is_regular_file()) {
        detail = "неожиданный тип объекта: " +
                 current.opened_policy_path().string();
        return ResourceOutcome::Conflict;
    }
    return transitionToBaseline(current, rule.baseline, detail);
}

const std::vector<fic::platform::FileAccessRule>* policyRules(
    const DacBaselineRollbackOptions& options,
    const std::string& policyName,
    MutationRollbackOutcome& outcome) {
    if (policyName == "systemcommandlock") {
        return &options.platform.protectedSystemCommands;
    }
    if (policyName == "blocking_user_access_to_system_files") {
        return &options.platform.protectedSystemFiles;
    }
    outcome.status = RollbackStatus::Unsupported;
    outcome.message = "Policy '" + policyName +
                      "' не поддерживает platform-baseline rollback";
    return nullptr;
}

} // namespace

MutationRollbackOutcome undoDacBaselineMutation(
    const DacBaselineRollbackOptions& options,
    const MutationRecord& record,
    const UndoApplyDacPlatformBaseline& undo) {
    const std::lock_guard<std::mutex> lock(dacBaselineMutex());

    MutationRollbackOutcome outcome;
    outcome.id = record.id;
    outcome.resource = record.resource;

    const std::vector<fic::platform::FileAccessRule>* rules =
        policyRules(options, undo.policyName, outcome);
    if (rules == nullptr) {
        return outcome;
    }
    if (rules->empty()) {
        outcome.status = RollbackStatus::Failed;
        outcome.message =
            "Platform profile не содержит управляемых объектов для policy '" +
            undo.policyName + "'";
        return outcome;
    }

    int applied = 0;
    int compliant = 0;
    int conflicts = 0;
    int failed = 0;
    std::string firstDetail;
    for (const fic::platform::FileAccessRule& rule : *rules) {
        std::string detail;
        const ResourceOutcome result = rollbackFileAccessRule(rule, detail);
        switch (result) {
        case ResourceOutcome::Applied: ++applied; break;
        case ResourceOutcome::Compliant: ++compliant; break;
        case ResourceOutcome::Conflict: ++conflicts; break;
        case ResourceOutcome::Failed: ++failed; break;
        }
        if (!detail.empty() && firstDetail.empty()) {
            firstDetail = rule.path.string() + ": " + detail;
        }
    }

    // TCB dynamic resources: only the actually existing tree is touched,
    // and only when this policy manages TCB storage.
    int tcbApplied = 0;
    int tcbCompliant = 0;
    int tcbFailed = 0;
    if (undo.policyName == "blocking_user_access_to_system_files" &&
        options.platform.tcbCredentialStorage) {
        const TcbBaselineRollbackReport tcb = rollbackTcbTreeToBaseline(
            *options.platform.tcbCredentialStorage);
        tcbApplied = tcb.applied;
        tcbCompliant = tcb.compliant;
        tcbFailed = tcb.failed;
        if (tcb.failed != 0 && firstDetail.empty()) {
            firstDetail = "TCB: " + tcb.firstError;
        }
    }

    const int totalFailures = failed + conflicts + tcbFailed;
    const int totalApplied = applied + tcbApplied;
    const int totalCompliant = compliant + tcbCompliant;
    if (totalFailures == 0) {
        if (totalApplied == 0) {
            // baseline -> baseline is a no-op: repeated rollback is
            // idempotent and explicitly reported as NothingToDo.
            outcome.status = RollbackStatus::NothingToDo;
            outcome.message =
                "Все управляемые объекты уже в platform baseline "
                "(объектов в baseline: " +
                std::to_string(totalCompliant) + ")";
        } else {
            outcome.status = RollbackStatus::Success;
            outcome.message =
                "Platform baseline применен к " +
                std::to_string(totalApplied) + " объектам (уже в baseline: " +
                std::to_string(totalCompliant) + ")";
        }
        return outcome;
    }
    if (totalApplied > 0 || totalCompliant > 0) {
        // Partial failure: report honestly instead of a fake success; the
        // journal record is not resolved so a repeated disable retries.
        outcome.status = RollbackStatus::Partial;
        outcome.message = "Rollback выполнен частично: применено " +
                          std::to_string(totalApplied) + ", уже в baseline " +
                          std::to_string(totalCompliant) + ", с ошибками " +
                          std::to_string(totalFailures) +
                          (firstDetail.empty() ? "" : ("; " + firstDetail));
        return outcome;
    }
    outcome.status = conflicts > 0 ? RollbackStatus::Conflict
                                   : RollbackStatus::Failed;
    outcome.message = firstDetail.empty()
        ? "Platform baseline rollback не выполнен"
        : firstDetail;
    return outcome;
}

DacBaselineOwnershipVerdict checkDacBaselineOwnership(
    const DacBaselineRollbackOptions& options,
    const std::string& policyName,
    std::string& error) {
    const std::lock_guard<std::mutex> lock(dacBaselineMutex());

    MutationRollbackOutcome probe;
    const std::vector<fic::platform::FileAccessRule>* rules =
        policyRules(options, policyName, probe);
    if (rules == nullptr) {
        error = probe.message;
        return DacBaselineOwnershipVerdict::Unproven;
    }

    bool enforcedPresent = false;
    for (const fic::platform::FileAccessRule& rule : *rules) {
        std::vector<std::filesystem::path> allowedTargets =
            rule.allowedFinalSymlinkTargets;
        for (const auto& target : rule.providerManagedFinalSymlinkTargets) {
            allowedTargets.push_back(target.path);
        }
        FileStats current = FileStats::openPolicyPath(
            rule.path.string(), allowedTargets,
            PolicyPathResolution::Standard);
        if (current.is_missing()) {
            continue;
        }
        if (current.has_error()) {
            // Unsafe object: ownership cannot be proven, fail closed.
            error = rule.path.string() + ": " + current.error_message();
            return DacBaselineOwnershipVerdict::Unproven;
        }

        const auto providerTarget = std::find_if(
            rule.providerManagedFinalSymlinkTargets.begin(),
            rule.providerManagedFinalSymlinkTargets.end(),
            [&](const auto& target) {
                return target.path == current.opened_policy_path();
            });
        if (providerTarget !=
                rule.providerManagedFinalSymlinkTargets.end()) {
            // Provider targets are validate-only during enforcement, so they
            // cannot prove FIC ownership; they are never remediated by apply.
            continue;
        }

        uid_t enforcedOwnerId = 0;
        gid_t enforcedGroupId = 0;
        if (!FileStats::resolve_owner_group(
                rule.enforced.owner, rule.enforced.group,
                enforcedOwnerId, enforcedGroupId)) {
            error = rule.path.string() + ": identity resolution failed";
            return DacBaselineOwnershipVerdict::Unproven;
        }
        const mode_t currentPermissions = current._permissions & 07777;
        const bool ownershipMatchesEnforced =
            current.owner_id() == enforcedOwnerId &&
            current.group_id() == enforcedGroupId;
        // MaximumAllowed enforcement may leave the mode stricter than the
        // enforced profile value; any state at or below the enforced mode
        // with enforced ownership is FIC's enforced state.
        if (ownershipMatchesEnforced &&
            (currentPermissions & ~rule.enforced.permissions) == 0) {
            enforcedPresent = true;
            continue;
        }
        // Anything that is neither enforced (or stricter) nor baseline is a
        // foreign state: refuse disable without journal provenance.
        uid_t baselineOwnerId = 0;
        gid_t baselineGroupId = 0;
        if (!FileStats::resolve_owner_group(
                rule.baseline.owner, rule.baseline.group,
                baselineOwnerId, baselineGroupId)) {
            error = rule.path.string() + ": identity resolution failed";
            return DacBaselineOwnershipVerdict::Unproven;
        }
        const bool baselineHere =
            current.owner_id() == baselineOwnerId &&
            current.group_id() == baselineGroupId &&
            currentPermissions == (rule.baseline.permissions & 07777);
        if (!baselineHere) {
            error = rule.path.string() +
                    ": объект не находится ни в enforced, ни в baseline " +
                    "состоянии";
            return DacBaselineOwnershipVerdict::Unproven;
        }
    }
    return enforcedPresent
        ? DacBaselineOwnershipVerdict::Owned
        : DacBaselineOwnershipVerdict::AtBaseline;
}

} // namespace fic::rollback