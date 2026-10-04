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
    const MutationId preparedId = prepared->id;

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
        // Durability BEFORE commit: the wrapper being VISIBLE proves nothing if
        // the rename that published it was never followed by a directory fsync.
        std::string durabilityError;
        if (!deps_.journal.proveDurable(proofPaths(target), durabilityError)) {
            outcome.result = PreparedRecoveryResult::FailClosed;
            outcome.message =
                "target-состояние не подтверждено durable; Prepared-запись "
                "оставлена активной";
            outcome.diagnostics.push_back(durabilityError);
            return outcome;
        }
        // Ownership is re-proved against the exact target set immediately
        // before the journal may claim it.
        const std::string refusal =
            transaction.validateCurrentOwnership(target);
        if (!refusal.empty()) {
            outcome.result = PreparedRecoveryResult::FailClosed;
            outcome.message =
                "target-состояние не доказано перед commit: " + refusal;
            return outcome;
        }
        std::string commitError;
        if (!deps_.journal.commit(preparedId, commitError)) {
            outcome.result = PreparedRecoveryResult::FailClosed;
            outcome.message =
                "не удалось зафиксировать существующую Prepared-запись: " +
                commitError;
            return outcome;
        }
        outcome.result = PreparedRecoveryResult::CommittedExisting;
        outcome.message =
            "Prepared-запись доказанно завершена, durable и переведена в "
            "Applied";
        return outcome;
    }

    if (classification == PreparedRecovery::CompletePrevious) {
        // Durability BEFORE discarding/normalizing: the previous side may
        // itself have been produced by a compensation rename whose directory
        // fsync never completed.
        std::string durabilityError;
        const std::vector<SudoScopedDefaultsWrapperProof>& provenSide =
            previous.empty() ? target : previous;
        if (!deps_.journal.proveDurable(proofPaths(provenSide),
                                        durabilityError)) {
            outcome.result = PreparedRecoveryResult::FailClosed;
            outcome.message =
                "previous-состояние не подтверждено durable; Prepared-запись "
                "оставлена активной";
            outcome.diagnostics.push_back(durabilityError);
            return outcome;
        }
        if (previous.empty()) {
            // FRESH transition that provably never landed: nothing is owned, so
            // removing the record loses no provenance.
            std::string discardError;
            if (!deps_.journal.discard(preparedId, discardError)) {
                outcome.result = PreparedRecoveryResult::FailClosed;
                outcome.message =
                    "не удалось закрыть доказанно неприменённую "
                    "Prepared-запись: " + discardError;
                return outcome;
            }
            outcome.result = PreparedRecoveryResult::DiscardedExisting;
            outcome.message =
                "Prepared-запись доказанно не была применена и закрыта";
            return outcome;
        }
        // REFRESH: the physical wrappers of `previous` are on disk and were
        // proven by FIC BEFORE this transition. Discarding here would orphan
        // them, so the record is normalized back to Applied(previous) instead.
        const std::string refusal =
            transaction.validateCurrentOwnership(previous);
        if (!refusal.empty()) {
            outcome.result = PreparedRecoveryResult::FailClosed;
            outcome.message =
                "previous-состояние не доказано перед normalization: " + refusal;
            return outcome;
        }
        std::string normalizeError;
        if (!deps_.journal.normalizePreparedToPrevious(preparedId, previous,
                                                       normalizeError)) {
            outcome.result = PreparedRecoveryResult::FailClosed;
            outcome.message =
                "не удалось вернуть refresh-запись к previous-владению: " +
                normalizeError;
            return outcome;
        }
        outcome.result = PreparedRecoveryResult::NormalizedExisting;
        outcome.message =
            "неудачный refresh откатан к прежнему доказанному владению";
        return outcome;
    }

    // Indeterminate: prefer an EXACT selective compensation of the target-only
    // wrappers back to the previous side. Anything unprovable fails closed and
    // keeps the Prepared record active.
    SudoScopedDefaultsFilesystemState state =
        SudoScopedDefaultsFilesystemState::Unchanged;
    std::string compensationError;
    if (transaction.compensateToPrevious(previous, target, deps_.hooks, state,
                                         compensationError)) {
        if (previous.empty()) {
            std::string discardError;
            if (!deps_.journal.discard(preparedId, discardError)) {
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
        // REFRESH compensation: the surviving previous wrappers must stay
        // authorized, so the record is normalized instead of discarded.
        std::string normalizeError;
        if (!deps_.journal.normalizePreparedToPrevious(preparedId, previous,
                                                       normalizeError)) {
            outcome.result = PreparedRecoveryResult::FailClosed;
            outcome.message =
                "компенсация выполнена, но refresh-запись не нормализована: " +
                normalizeError;
            return outcome;
        }
        outcome.result = PreparedRecoveryResult::CompensatedExisting;
        outcome.message =
            "частичный refresh компенсирован; владение возвращено к previous";
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

// Shared resolution of a Prepared record after a FAILED mutation, so the
// fresh-transition and refresh-transition behaviour is identical on every error
// path (pre-write conflict, CAS conflict, failed write, compensated write).
bool ScopedDefaultsLifecycle::resolveAfterFailedMutation(
    MutationId mutationId,
    const std::vector<SudoScopedDefaultsWrapperProof>& previous,
    const std::vector<SudoScopedDefaultsWrapperProof>& target,
    SudoScopedDefaultsFilesystemState state,
    ScopedDefaultsLifecycleOutcome& outcome) {
    if (!allowsDiscardPrepared(state)) {
        outcome.message =
            "состояние ФС не доказано как previous/unchanged; Prepared-запись "
            "остаётся активной";
        return false;
    }
    if (previous.empty()) {
        // FRESH: FIC owned nothing before this transition, so removing the
        // record loses no provenance.
        std::string discardError;
        if (!deps_.journal.discard(mutationId, discardError)) {
            outcome.message =
                "не удалось удалить подготовленную запись: " + discardError;
            return false;
        }
        return true;
    }
    // REFRESH: the previous wrappers are physically present and were proven by
    // FIC before this transition. Deleting the record would orphan them, so it
    // is normalized back to Applied(previous) on the SAME id.
    std::string durabilityError;
    if (!deps_.journal.proveDurable(proofPaths(previous), durabilityError)) {
        outcome.message =
            "previous-состояние не подтверждено durable; normalization "
            "запрещена, Prepared-запись остаётся активной";
        outcome.diagnostics.push_back(durabilityError);
        return false;
    }
    std::string normalizeError;
    if (!deps_.journal.normalizePreparedToPrevious(mutationId, previous,
                                                   normalizeError)) {
        outcome.message =
            "не удалось вернуть refresh-запись к previous-владению: " +
            normalizeError;
        return false;
    }
    return true;
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
        // The proven filesystem state decides the fate of the Prepared record,
        // and for a REFRESH the surviving previous ownership must be
        // normalized back, never discarded.
        if (allowsDiscardPrepared(applied.filesystemState)) {
            if (!resolveAfterFailedMutation(mutationId, owned, targetProofs,
                                            applied.filesystemState,
                                            outcome)) {
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

    // FINAL ownership re-proof against the exact TARGET set. The initial
    // preflight ran before the mutation; between then and here an external
    // process may have edited an already-owned wrapper, and committing
    // targetProofs in that case would authorize content FIC never proved.
    std::string reloadError;
    if (deps_.configuration != nullptr &&
        !deps_.configuration->load(reloadError)) {
        outcome.message = "не удалось перечитать sudoers перед commit: " +
                          reloadError;
        return outcome;
    }
    ScopedDefaultsTransaction finalTransaction(*deps_.configuration, policyName);
    const std::string finalRefusal =
        finalTransaction.validateCurrentOwnership(targetProofs);
    if (!finalRefusal.empty()) {
        // The filesystem holds installed FIC state, so the Prepared record MUST
        // stay active: recovery will resolve it from the real physical state.
        outcome.message =
            "финальное доказательство владения не пройдено, commit запрещён: " +
            finalRefusal;
        return outcome;
    }
    // Durability barrier before the journal may claim the target ownership.
    std::string durabilityError;
    if (!deps_.journal.proveDurable(proofPaths(targetProofs),
                                    durabilityError)) {
        outcome.message =
            "target-состояние не подтверждено durable; Prepared-запись "
            "оставлена активной";
        outcome.diagnostics.push_back(durabilityError);
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