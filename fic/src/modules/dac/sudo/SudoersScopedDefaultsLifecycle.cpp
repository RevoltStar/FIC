#include "modules/dac/sudo/SudoersScopedDefaultsLifecycle.h"

#include <map>
#include <utility>

namespace fic::sudoers {

ScopedDefaultsLifecycle::ScopedDefaultsLifecycle(
    ScopedDefaultsLifecycleDeps deps)
    : deps_(std::move(deps)) {}

bool ScopedDefaultsLifecycle::collectActiveOwnership(
    const std::vector<MutationRecord>& records,
    const std::string& resource,
    std::vector<SudoScopedDefaultsWrapperProof>& owned,
    std::string& error) {
    owned.clear();
    // At most ONE active logical record may own the canonical scoped-defaults
    // resource. Several active records (corruption or a legacy state) would
    // otherwise be concatenated into one plausible-looking proof set.
    const MutationRecord* found = nullptr;
    int count = 0;
    for (const MutationRecord& record : records) {
        if (!record.isActive() || record.resource != resource) {
            continue;
        }
        ++count;
        found = &record;
    }
    if (count > 1) {
        error = "обнаружено " + std::to_string(count) +
            " активных записей mutation journal для ресурса '" + resource +
            "' (ожидается максимум одна): fail closed";
        return false;
    }
    if (found == nullptr) {
        return true;
    }
    const auto* payload = std::get_if<UndoReleaseSudoScopedDefaults>(
        &found->undo.payload);
    if (payload == nullptr) {
        error = "активная запись mutation journal имеет неожиданный payload";
        return false;
    }
    owned.reserve(payload->targetProofs.size());
    for (const SudoScopedDefaultsWrapperProof& proof : payload->targetProofs) {
        owned.push_back(proof);
    }
    return true;
}

ScopedDefaultsRecoveryOutcome ScopedDefaultsLifecycle::recoverPrepared(
    const std::string& policyName) {
    ScopedDefaultsRecoveryOutcome outcome;
    const PolicyRef policy{std::string(kSudoModuleName),
                           std::string(kSudoSubmoduleName), policyName};

    const std::vector<MutationRecord> records =
        deps_.journal.activeRecords(policy);
    const MutationRecord* prepared = nullptr;
    for (const MutationRecord& record : records) {
        if (!record.isActive() || record.resource != kScopedDefaultsResource ||
            record.status != MutationStatus::Prepared) {
            continue;
        }
        prepared = &record;
        break;
    }
    if (prepared == nullptr) {
        return outcome; // NotPresent
    }

    const auto* payload = std::get_if<UndoReleaseSudoScopedDefaults>(
        &prepared->undo.payload);
    if (payload == nullptr) {
        outcome.result = PreparedRecoveryResult::FailClosed;
        outcome.message = "Prepared-запись SUDO имеет неожиданный payload";
        return outcome;
    }
    const std::vector<SudoScopedDefaultsWrapperProof> previous =
        payload->previousProofs;
    const std::vector<SudoScopedDefaultsWrapperProof> target =
        payload->targetProofs;

    // The graph is reloaded first: the live filesystem is the only evidence.
    if (deps_.configuration != nullptr) {
        std::string loadError;
        if (!deps_.configuration->load(loadError)) {
            outcome.result = PreparedRecoveryResult::FailClosed;
            outcome.message =
                "не удалось перечитать sudoers для восстановления Prepared: " +
                loadError;
            return outcome;
        }
    }
    ScopedDefaultsTransaction transaction(*deps_.configuration, policyName);
    std::string classifyError;
    const PreparedRecovery classification =
        transaction.classifyPrepared(previous, target, classifyError);
    if (classification == PreparedRecovery::CompleteTarget) {
        // The filesystem mutation provably completed and only the commit is
        // missing: the EXISTING record becomes Applied. No new ids are minted.
        std::string commitError;
        if (!deps_.journal.commit(prepared->id, commitError)) {
            outcome.result = PreparedRecoveryResult::FailClosed;
            outcome.message =
                "не удалось зафиксировать существующую Prepared-запись: " +
                commitError;
            return outcome;
        }
        outcome.result = PreparedRecoveryResult::CommittedExisting;
        outcome.message =
            "Prepared-запись доказанно завершена и переведена в Applied";
        return outcome;
    }
    if (classification == PreparedRecovery::CompletePrevious) {
        std::string discardError;
        if (!deps_.journal.discard(prepared->id, discardError)) {
            outcome.result = PreparedRecoveryResult::FailClosed;
            outcome.message =
                "не удалось закрыть доказанно неприменённую Prepared-запись: " +
                discardError;
            return outcome;
        }
        outcome.result = PreparedRecoveryResult::DiscardedExisting;
        outcome.message = "Prepared-запись доказанно не была применена и закрыта";
        return outcome;
    }

    // Indeterminate: prefer an EXACT compensation of the target-only wrappers
    // back to the previous side. Anything unprovable fails closed and keeps the
    // Prepared record active.
    SudoScopedDefaultsFilesystemState state =
        SudoScopedDefaultsFilesystemState::Unchanged;
    std::string compensationError;
    if (transaction.compensateToPrevious(previous, target, deps_.hooks, state,
                                         compensationError)) {
        std::string discardError;
        if (!deps_.journal.discard(prepared->id, discardError)) {
            outcome.result = PreparedRecoveryResult::FailClosed;
            outcome.message =
                "компенсация выполнена, но Prepared-запись не закрыта: " +
                discardError;
            return outcome;
        }
        outcome.result = PreparedRecoveryResult::CompensatedExisting;
        outcome.message =
            "частичная Prepared-запись компенсирована до previous-состояния";
        return outcome;
    }
    outcome.result = PreparedRecoveryResult::FailClosed;
    outcome.message =
        "неоднозначное состояние Prepared; владение не доказано, запись "
        "оставлена активной";
    outcome.diagnostics.push_back(compensationError);
    outcome.diagnostics.push_back(classifyError);
    return outcome;
}

ScopedDefaultsLifecycleOutcome ScopedDefaultsLifecycle::reconcile(
    const std::string& policyName) {
    ScopedDefaultsLifecycleOutcome outcome;
    const PolicyRef policy{std::string(kSudoModuleName),
                           std::string(kSudoSubmoduleName), policyName};
    if (deps_.configuration == nullptr) {
        outcome.message = "нет конфигурации sudoers для reconcile";
        return outcome;
    }

    // 1. An unresolved Prepared record is resolved BEFORE anything else. New
    //    wrapper ids are never minted on top of it.
    const ScopedDefaultsRecoveryOutcome recovery =
        recoverPrepared(policyName);
    outcome.diagnostics = recovery.diagnostics;
    if (recovery.result == PreparedRecoveryResult::FailClosed) {
        outcome.message = "восстановление Prepared-записи: " + recovery.message;
        return outcome;
    }

    // 2. Reload: recovery may have changed the filesystem, and planning must be
    //    computed from the current graph, never from a stale snapshot.
    std::string error;
    if (!deps_.configuration->load(error)) {
        outcome.message = "не удалось проанализировать sudoers: " + error;
        return outcome;
    }
    ScopedDefaultsTransaction transaction(*deps_.configuration, policyName);

    // 3. Current proven ownership. More than one active record fails closed.
    std::vector<SudoScopedDefaultsWrapperProof> owned;
    if (!collectActiveOwnership(deps_.journal.activeRecords(policy),
                                kScopedDefaultsResource, owned, error)) {
        outcome.message = error;
        return outcome;
    }

    // 4. EXISTING ownership is validated before ANY new mutation, so an orphan
    //    or drifted wrapper blocks reconciliation too, not just no-op.
    const std::string refusal = transaction.validateCurrentOwnership(owned);
    if (!refusal.empty()) {
        outcome.message = "состояние FIC-owned не доказано: " + refusal;
        return outcome;
    }
    outcome.owned = owned;

    const ScopedDefaultsPlan plan = transaction.plan(owned);
    if (plan.fresh.empty()) {
        outcome.ok = true;
        outcome.unchanged = true;
        outcome.message = "Активных контекстных Defaults не обнаружено";
        return outcome;
    }

    // 5. Journal the FULL ownership set BEFORE touching the filesystem.
    std::vector<SudoScopedDefaultsWrapperProof> targetProofs = owned;
    for (const PlannedScopedDefaultsMutation& mutation : plan.fresh) {
        targetProofs.push_back(mutation.proof);
    }
    UndoAction undo{MutationBackend::Sudo,
                    UndoReleaseSudoScopedDefaults{policyName, owned,
                                                  targetProofs}};
    MutationId mutationId = 0;
    std::string journalError;
    if (!deps_.journal.prepare(policy, kScopedDefaultsResource, undo, mutationId,
                               journalError)) {
        outcome.message =
            "не удалось подготовить запись mutation journal: " + journalError;
        return outcome;
    }

    // 6. Run the filesystem transaction.
    const SudoScopedDefaultsTransactionResult applied =
        transaction.apply(plan.fresh, deps_.hooks);
    outcome.diagnostics.insert(outcome.diagnostics.end(),
                               applied.operation.diagnostics.begin(),
                               applied.operation.diagnostics.end());
    if (!applied.ok()) {
        // The ONLY thing that decides the fate of the Prepared record is the
        // proven filesystem state, never the reason of the failure.
        if (allowsDiscardPrepared(applied.filesystemState)) {
            std::string discardError;
            if (!deps_.journal.discard(mutationId, discardError)) {
                outcome.message = "не удалось удалить подготовленную запись: " +
                                  discardError;
                return outcome;
            }
        } else {
            outcome.message =
                "мутация не компенсирована; подготовленная запись journal "
                "остаётся активной";
            outcome.diagnostics.push_back(applied.operation.message);
            return outcome;
        }
        outcome.message = applied.operation.message;
        return outcome;
    }

    if (!deps_.journal.commit(mutationId, journalError)) {
        outcome.message =
            "мутация применена, но запись mutation journal не зафиксирована: " +
            journalError;
        return outcome;
    }
    outcome.ok = true;
    outcome.owned = targetProofs;
    outcome.message = applied.operation.message;
    return outcome;
}

} // namespace fic::sudoers