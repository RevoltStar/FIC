#include "modules/dac/sudo/SudoersScopedDefaultsLifecycle.h"

#include <map>
#include <set>
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


// STRICT snapshot-bound resolution proof.
//
// capture -> prove (exact ownership + semantics on the SAME captures) ->
// durability of EXACTLY those captures. A journal transition may only follow
// this sequence; nothing re-reads the filesystem in between.
bool ScopedDefaultsLifecycle::proveStrictState(
    const std::string& policyName,
    const std::vector<SudoScopedDefaultsWrapperProof>& proofs,
    ScopedDefaultsCapturedState& captured,
    std::string& error,
    bool requireNoActiveScopedDefaults) {
    ScopedDefaultsTransaction transaction(*deps_.configuration, policyName);
    if (!transaction.captureProofAndGraphState(proofs, captured, error)) {
        return false;
    }
    const ScopedDefaultsStateProof proof = transaction.proveCapturedState(
        proofs, captured, ScopedDefaultsProofMode::Exact,
        requireNoActiveScopedDefaults);
    if (!proof.ok) {
        error = proof.message;
        return false;
    }
    if (!ScopedDefaultsTransaction::proveCapturedStateDurable(proof.captured,
                                                               error)) {
        return false;
    }
    captured = proof.captured;
    return true;
}


bool ScopedDefaultsLifecycle::verifyTopologyUnchanged(
    const char* stage, std::string& error) const {
    if (deps_.configuration == nullptr) {
        error = "нет конфигурации sudoers";
        return false;
    }
    std::string verifyError;
    if (!deps_.configuration->verifyIncludedDirectoryTopologyUnchanged(
            verifyError)) {
        error = std::string("топология @includedir изменилась (") + stage +
                "), доказательство недействительно: " + verifyError;
        return false;
    }
    return true;
}

bool ScopedDefaultsLifecycle::provePreviousResolution(
    const std::string& policyName,
    const std::vector<SudoScopedDefaultsWrapperProof>& previousProofs,
    const std::vector<SudoScopedDefaultsWrapperProof>& targetProofs,
    ScopedDefaultsCapturedState& captured,
    std::string& error) {
    // Capture scope = current graph U previous paths U target paths.
    //
    // The TARGET paths matter: a target-only wrapper may have fallen out of the
    // current include graph (topology change) and would otherwise be invisible.
    // The semantic invariant is deliberately NOT required: an unresolved refresh
    // legitimately leaves the new violation active.
    std::vector<fic::sudoers::SudoScopedDefaultsWrapperProof> allProofs =
        previousProofs;
    allProofs.insert(allProofs.end(), targetProofs.begin(), targetProofs.end());
    ScopedDefaultsTransaction transaction(*deps_.configuration, policyName);
    if (!transaction.captureProofAndGraphState(allProofs, captured, error)) {
        return false;
    }
    // Exact(previous) on the FULL capture already proves everything needed:
    //   * every previous wrapper exists exactly once, at its exact
    //     canonicalPath, with its exact payload digest;
    //   * ANY surviving target-only wrapper is an UNKNOWN wrapper for this
    //     expected set and therefore fails closed;
    //   * duplicate ids, drift and malformed markers fail closed.
    //
    // A separate FullyReleased(targetOnly) check is deliberately NOT used: that
    // mode is the whole-policy TERMINAL contract (no FIC wrapper of the policy
    // may survive) used by fresh discard and rollback Success/NothingToDo. It
    // would wrongly demand the absence of the previous wrapper A that must
    // survive a refresh rewind.
    const ScopedDefaultsStateProof exact = transaction.proveCapturedState(
        previousProofs, captured, ScopedDefaultsProofMode::Exact, false);
    if (!exact.ok) {
        error = "previous-состояние не доказано: " + exact.message;
        return false;
    }
    // Durability of EXACTLY the capture that was just proven.
    return ScopedDefaultsTransaction::proveCapturedStateDurable(exact.captured,
                                                               error);
}

bool ScopedDefaultsLifecycle::resolveFreshPreparedToNoOwnership(
    MutationId mutationId,
    const std::vector<SudoScopedDefaultsWrapperProof>& targetProofs,
    ScopedDefaultsLifecycleOutcome& outcome) {
    if (deps_.configuration == nullptr) {
        outcome.message = "нет конфигурации sudoers";
        return false;
    }
    ScopedDefaultsTransaction transaction(*deps_.configuration, kScopedDefaultsPolicyName);
    ScopedDefaultsCapturedState captured;
    std::string error;
    if (!transaction.captureProofAndGraphState(targetProofs, captured, error)) {
        outcome.message = "не удалось захватить sudoers-пути: " + error;
        return false;
    }
    // FullyReleased on THAT capture, then durability of THAT capture. The
    // filesystem merely LOOKING like the previous side is not enough.
    const ScopedDefaultsStateProof proof = transaction.proveCapturedState(
        targetProofs, captured, ScopedDefaultsProofMode::FullyReleased, false);
    if (!proof.ok) {
        outcome.message = "target-владение не доказано отсутствующим: " +
                          proof.message;
        return false;
    }
    if (!ScopedDefaultsTransaction::proveCapturedStateDurable(proof.captured,
                                                               error)) {
        outcome.message = "отсутствие target-владения не durable: " + error;
        return false;
    }
    // Discarding on "the filesystem looks like the previous side" is only valid
    // for the loaded graph: a new @includedir member could bring a wrapper that
    // must NOT be released, so membership is re-proved before the transition.
    if (deps_.journal.beforeFinalTopologyGuard) {
        deps_.journal.beforeFinalTopologyGuard();
    }
    std::string discardTopologyError;
    if (!verifyTopologyUnchanged("discard", discardTopologyError)) {
        outcome.message = discardTopologyError;
        return false;
    }
    std::string discardError;
    if (!deps_.journal.discard(mutationId, discardError)) {
        outcome.message = "не удалось удалить подготовленную запись: " +
                          discardError;
        return false;
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
    // Capture set = current graph UNION every previous/target proof path. The
    // current include graph is NOT the recovery authority: a wrapper may still
    // exist physically while the @include/@includedir topology changed, and
    // classifying from the graph alone would conclude CompletePrevious and
    // discard a record that still owns a physical wrapper.
    std::vector<fic::sudoers::SudoScopedDefaultsWrapperProof> allProofs = previous;
    allProofs.insert(allProofs.end(), target.begin(), target.end());
    ScopedDefaultsCapturedState captured;
    std::string captureError;
    if (!transaction.captureProofAndGraphState(allProofs, captured,
                                               captureError)) {
        outcome.result = PreparedRecoveryResult::FailClosed;
        outcome.message = "не удалось захватить sudoers-пути: " + captureError;
        return outcome;
    }
    std::string classifyError;
    const PreparedRecovery classification = transaction.classifyCaptured(
        previous, target, captured, classifyError);
    if (classification == PreparedRecovery::CompleteTarget) {
        // STRICT: capture, prove the EXACT target set (including that every
        // target wrapper physically exists) and the semantic invariant on those
        // same captures, then confirm durability of exactly those captures.
        ScopedDefaultsCapturedState captured;
        std::string strictError;
        if (!proveStrictState(policyName, target, captured, strictError)) {
            outcome.result = PreparedRecoveryResult::FailClosed;
            outcome.message =
                "target-состояние не доказано (snapshot/durability): " +
                strictError;
            return outcome;
        }
        if (deps_.journal.beforeFinalTopologyGuard) {
            deps_.journal.beforeFinalTopologyGuard();
        }
        std::string recoveryTopologyError;
        if (!verifyTopologyUnchanged("commit существующей Prepared", recoveryTopologyError)) {
            // Never NotPresent: reconcile() continues on any non-FailClosed
            // result, which would treat an unresolved Prepared record as if it
            // did not exist.
            outcome.result = PreparedRecoveryResult::FailClosed;
            outcome.message = recoveryTopologyError;
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
        if (previous.empty()) {
            // FRESH transition: the filesystem provably holds no FIC-owned
            // wrapper, so there is nothing to prove and nothing to orphan. Only
            // the removal of the record is required.
            ScopedDefaultsLifecycleOutcome discardOutcome;
            if (!resolveFreshPreparedToNoOwnership(preparedId, target,
                                                    discardOutcome)) {
                outcome.result = PreparedRecoveryResult::FailClosed;
                outcome.message = discardOutcome.message +
                                  "; Prepared-запись оставлена активной";
                return outcome;
            }
            outcome.result = PreparedRecoveryResult::DiscardedExisting;
            outcome.message =
                "Prepared-запись доказанно не была применена и закрыта";
            return outcome;
        }
        // REFRESH: the physical wrappers of `previous` are on disk and were
        // proven by FIC BEFORE this transition. Classification is NOT the
        // resolution authority: a final snapshot-bound previous-resolution proof
        // (graph U previous U target paths, Exact, same-capture durability)
        // decides. Discarding here would orphan them.
        {
            ScopedDefaultsCapturedState captured;
            std::string strictError;
            if (!provePreviousResolution(policyName, previous, target, captured,
                                         strictError)) {
                outcome.result = PreparedRecoveryResult::FailClosed;
                outcome.message =
                    "previous-состояние не доказано (snapshot/durability): " +
                    strictError;
                return outcome;
            }
        }
        if (deps_.journal.beforeFinalTopologyGuard) {
            deps_.journal.beforeFinalTopologyGuard();
        }
        std::string normalizeTopologyError;
        if (!verifyTopologyUnchanged("normalize к previous",
                                     normalizeTopologyError)) {
            // A topology failure with an ACTIVE Prepared record must NEVER be
            // reported as NotPresent: reconcile() only stops early on
            // FailClosed, so defaulting here would let it continue and mint new
            // wrapper ids on top of an unresolved record.
            outcome.result = PreparedRecoveryResult::FailClosed;
            outcome.message = normalizeTopologyError;
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
            // NEW post-compensation capture: the PRE-compensation snapshot may
            // not be reused for the release decision.
            ScopedDefaultsLifecycleOutcome discardOutcome;
            if (!resolveFreshPreparedToNoOwnership(preparedId, target,
                                                    discardOutcome)) {
                outcome.result = PreparedRecoveryResult::FailClosed;
                outcome.message = discardOutcome.message;
                return outcome;
            }
            outcome.result = PreparedRecoveryResult::CompensatedExisting;
            outcome.message =
                "частичная Prepared-запись компенсирована до previous-состояния";
            return outcome;
        }
        // REFRESH compensation: the surviving previous wrappers must stay
        // authorized, so the record is normalized instead of discarded.
        // Compensated != ExactPrevious. compensateToPrevious() only proves the
        // files it rewrote; an external writer may have touched a previous
        // wrapper in a file the transaction never touched. A NEW post-operation
        // capture must therefore re-prove the exact previous state before the
        // journal may be normalized.
        if (deps_.journal.afterPreparedCompensation) {
            deps_.journal.afterPreparedCompensation();
        }
        {
            ScopedDefaultsCapturedState finalPrevious;
            std::string proofError;
            if (!provePreviousResolution(policyName, previous, target,
                                         finalPrevious, proofError)) {
                outcome.result = PreparedRecoveryResult::FailClosed;
                outcome.message =
                    "post-compensation previous-состояние не доказано: " +
                    proofError;
                return outcome;
            }
        }
        if (deps_.journal.beforeFinalTopologyGuard) {
            deps_.journal.beforeFinalTopologyGuard();
        }
        std::string compensationTopologyError;
        if (!verifyTopologyUnchanged("normalize к previous после компенсации",
                                     compensationTopologyError)) {
            outcome.result = PreparedRecoveryResult::FailClosed;
            outcome.message = compensationTopologyError;
            return outcome;
        }
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
        // FRESH: still no discard without a final FullyReleased proof on a
        // fresh capture -- this holds for Unchanged AND for Compensated.
        return resolveFreshPreparedToNoOwnership(mutationId, target, outcome);
    }
    // REFRESH: the previous wrappers must still exist EXACTLY and durably. A
    // drifted or vanished A forbids the normalization, because normalizing would
    // authorize a wrapper FIC can no longer prove.
    {
        // graph U previous paths U target paths, Exact(previous), durability of
        // the SAME capture.
        ScopedDefaultsCapturedState captured;
        std::string strictError;
        if (!provePreviousResolution(kScopedDefaultsPolicyName, previous,
                                     target, captured, strictError)) {
            outcome.message =
                "previous-состояние не доказано (snapshot/durability), "
                "normalization запрещена: " + strictError;
            return false;
        }
    }
    if (deps_.journal.beforeFinalTopologyGuard) {
        deps_.journal.beforeFinalTopologyGuard();
    }
    std::string normalizeTopologyError;
    if (!verifyTopologyUnchanged("normalize к previous после неудачной мутации",
                                 normalizeTopologyError)) {
        outcome.message = normalizeTopologyError;
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
        // A no-op is a SECURITY-SENSITIVE decision: "there is nothing to do" is
        // only true for the filesystem state that was actually proven.
        //
        // AUTHORITY ORDER. Topology membership alone does NOT prove file
        // contents: an external process may rewrite an EXISTING member, keeping
        // the filename set identical while activating a scoped Defaults that
        // plan() never saw, because plan() reads the earlier graph snapshot. So
        // the CONTENT side is proven first, on a FRESH capture:
        //   capture(graph U owned proof paths)
        //     -> ReleaseSubset ownership proof (a missing proven wrapper stays
        //        an externally released subset, which is the existing contract)
        //     -> semantic invariant on THAT capture: no active scoped Defaults
        // A drifted, unknown, duplicated or malformed wrapper, or an active
        // scoped Defaults visible only in the new capture, fails closed.
        //
        // The TOPOLOGY guard is deliberately LAST. A brand-new @includedir member
        // cannot be discovered by a capture built from the previously loaded
        // graph: captureProofAndGraphState() only knows the graph documents and
        // the journal proof paths, so a member that appears after the capture
        // is invisible to the semantic proof. Verifying membership as the FINAL
        // action closes exactly that window, and nothing filesystem-related is
        // read between the guard and the unchanged success.
        if (deps_.journal.beforeNoOpSemanticCapture) {
            deps_.journal.beforeNoOpSemanticCapture();
        }
        ScopedDefaultsCapturedState noopCaptured;
        std::string noopCaptureError;
        if (!transaction.captureProofAndGraphState(owned, noopCaptured,
                                                   noopCaptureError)) {
            outcome.message =
                "не удалось захватить sudoers-пути для проверки no-op: " +
                noopCaptureError;
            return outcome;
        }
        const ScopedDefaultsStateProof noopProof =
            transaction.proveCapturedState(
                owned, noopCaptured, ScopedDefaultsProofMode::ReleaseSubset,
                /*requireNoActiveScopedDefaults=*/true);
        if (!noopProof.ok) {
            outcome.message =
                "no-op не доказан на актуальном состоянии файлов: " +
                noopProof.message;
            return outcome;
        }

        if (deps_.journal.beforeNoOpFinalTopologyGuard) {
            deps_.journal.beforeNoOpFinalTopologyGuard();
        }
        std::string topologyError;
        if (!verifyTopologyUnchanged("no-op", topologyError)) {
            outcome.message = topologyError;
            return outcome;
        }
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

    // STRICT FINAL SNAPSHOT: capture -> exact target ownership AND the semantic
    // invariant on THOSE captures -> durability of EXACTLY those captures.
    // A wrapper that disappeared after the transaction, an edited existing
    // wrapper or a re-activated scoped Defaults all fail here, and no unrelated
    // filesystem read happens between the proof and the barrier.
    {
        ScopedDefaultsCapturedState captured;
        std::string strictError;
        if (!proveStrictState(policyName, targetProofs, captured,
                              strictError)) {
            // The filesystem holds installed FIC state, so the Prepared record
            // MUST stay active: recovery resolves it from the real state.
            outcome.message =
                "строгое доказательство target-состояния не пройдено, commit "
                "запрещён: " + strictError;
            return outcome;
        }
    }

    // The strict proof above is bound to the captured files, but a brand-new
    // @includedir member is invisible to every capture path. Re-prove membership
    // in the exact window between the proof and the journal transition.
    if (deps_.journal.beforeFinalTopologyGuard) {
        deps_.journal.beforeFinalTopologyGuard();
    }
    std::string finalTopologyError;
    if (!verifyTopologyUnchanged("commit", finalTopologyError)) {
        outcome.message = finalTopologyError;
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