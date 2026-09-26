#include "modules/identity_access/pam/PamPasswordTopologyTransitionExecutor.h"

#include "modules/identity_access/pam/PamManagedPasswordSlots.h"

#include <fic/core/process/VerifiedProcessExecutor.h>

#include <algorithm>
#include <utility>

namespace fic::identity::pam {
namespace {

constexpr std::chrono::seconds kPamAuthUpdateTimeout{30};

std::string processFailure(const ProcessResult& result) {
    if (!result.error.empty()) {
        return result.error;
    }
    if (result.timedOut) {
        return "pam-auth-update timed out";
    }
    return "pam-auth-update exited with code " +
        std::to_string(result.exitCode) +
        (result.standardError.empty() ? "" : ": " + result.standardError);
}

bool isAttach(PamPasswordPlanActionKind kind) {
    return kind == PamPasswordPlanActionKind::AttachFicQuality ||
        kind == PamPasswordPlanActionKind::AttachFicHistoryInitial ||
        kind == PamPasswordPlanActionKind::AttachFicHistoryConsumer;
}

bool selectionFlagFor(
    const PamPasswordSelections& selections,
    PamPasswordPlanActionKind kind) {
    switch (kind) {
    case PamPasswordPlanActionKind::AttachFicQuality:
    case PamPasswordPlanActionKind::DetachFicQuality:
        return selections.ficQualitySelected;
    case PamPasswordPlanActionKind::AttachFicHistoryConsumer:
    case PamPasswordPlanActionKind::DetachFicHistoryConsumer:
        return selections.ficHistorySelected;
    case PamPasswordPlanActionKind::AttachFicHistoryInitial:
    case PamPasswordPlanActionKind::DetachFicHistoryInitial:
        return selections.ficHistoryInitialSelected;
    }
    return false;
}

} // namespace

PamPasswordTopologyTransitionExecutor::PamPasswordTopologyTransitionExecutor(
    fic::rollback::MutationJournal& journal,
    const fic::platform::PlatformExecutableResolver& executables,
    PamPasswordTopologyExecutorOptions options,
    std::filesystem::path configDirectory,
    std::filesystem::path stateDirectory)
    : journal_(journal),
      executables_(executables),
      options_(std::move(options)),
      configDirectory_(std::move(configDirectory)),
      stateDirectory_(std::move(stateDirectory)),
      qualityWriter_(configDirectory_, journal_,
                     PamManagedPasswordDomain::Quality),
      historyWriter_(configDirectory_, journal_,
                     PamManagedPasswordDomain::History) {
    inspectionOptions_.configDirectory = configDirectory_;
    inspectionOptions_.stateDirectory = stateDirectory_;
}

void PamPasswordTopologyTransitionExecutor::
    setQualitySlotFaultHooksForTests(
        SlotFaultHook beforeWrite, SlotFaultHook afterWrite) {
    qualityWriter_.setBeforeSlotWriteHookForTests(std::move(beforeWrite));
    qualityWriter_.setAfterSlotWriteHookForTests(std::move(afterWrite));
}

void PamPasswordTopologyTransitionExecutor::
    setHistorySlotFaultHooksForTests(
        SlotFaultHook beforeWrite, SlotFaultHook afterWrite) {
    historyWriter_.setBeforeSlotWriteHookForTests(std::move(beforeWrite));
    historyWriter_.setAfterSlotWriteHookForTests(std::move(afterWrite));
}

void PamPasswordTopologyTransitionExecutor::
    setQualityJournalCompletionFaultHookForTests(
        JournalCompletionFaultHook hook) {
    qualityWriter_.setJournalCompletionFaultHookForTests(std::move(hook));
}

void PamPasswordTopologyTransitionExecutor::
    setHistoryJournalCompletionFaultHookForTests(
        JournalCompletionFaultHook hook) {
    historyWriter_.setJournalCompletionFaultHookForTests(std::move(hook));
}

void PamPasswordTopologyTransitionExecutor::
    setHistoryC2CompensationFaultHookForTests(
        C2CompensationFaultHook hook) {
    historyWriter_.setC2CompensationFaultHookForTests(std::move(hook));
}

bool PamPasswordTopologyTransitionExecutor::runPamAuthUpdateOne(
    const char* flag, const char* profileId, std::string& error) {
    // Hard contract: exactly ONE profile per pam-auth-update invocation.
    std::filesystem::path executable;
    if (options_.runner) {
        // Test seam: the fake native mutator replaces the whole process
        // execution, so no production executable resolution happens.
        executable = "pam-auth-update";
    } else if (!executables_.resolve(
            fic::platform::ExecutableId::PamAuthUpdate, executable,
            error)) {
        error = "cannot resolve pam-auth-update: " + error;
        return false;
    }
    const std::vector<std::string> arguments{flag, profileId};
    ProcessOptions processOptions;
    processOptions.timeout = kPamAuthUpdateTimeout;
    processOptions.clearEnvironment = true;
    ProcessResult result;
    if (options_.runner) {
        result = options_.runner(
            executable.string(), arguments, processOptions);
    } else {
        result = VerifiedProcessExecutor::execute(
            executable.string(), arguments, processOptions);
    }
    if (!result.success()) {
        error = "pam-auth-update failed: " + processFailure(result);
        return false;
    }
    error.clear();
    return true;
}

bool PamPasswordTopologyTransitionExecutor::inspectFresh(
    PamPasswordTopologySnapshot& snapshot, std::string& error) {
    return inspectPamPasswordTopology(
        inspectionOptions_, journal_, snapshot, error);
}

bool PamPasswordTopologyTransitionExecutor::requireUsableCurrentState(
    const PamPasswordTopologySnapshot& snapshot, std::string& error) {
    if (!snapshot.coherenceError.empty()) {
        error = "current physical password topology is incoherent (fail "
                "closed): " +
            snapshot.coherenceError;
        return false;
    }
    // The foreign-added-during-FIC state is deliberately NOT attach-safe
    // (classification.valid == false), but the ownership-aware disable
    // path (detach-only plans) must be able to run from it.
    const bool usableClass =
        snapshot.classification.valid ||
        snapshot.classification.topologyClass ==
            PamPasswordTopologyClass::ForeignQualityPlusFicQuality;
    if (!usableClass) {
        error = "current physical password topology is not usable (fail "
                "closed): " +
            snapshot.classification.detail;
        return false;
    }
    if (!snapshot.safety.safe) {
        error = "current physical password topology is not C2-safe (fail "
                "closed): " +
            snapshot.safety.reason;
        return false;
    }
    std::string semanticsError;
    if (!provePamPasswordTopologySemantics(snapshot, semanticsError)) {
        error = "current physical password topology failed the semantic "
                "proof (fail closed): " +
            semanticsError;
        return false;
    }
    return true;
}

bool PamPasswordTopologyTransitionExecutor::driftGate(
    const PamPasswordTopologySnapshot& expected, std::string& error) {
    PamPasswordTopologySnapshot fresh;
    if (!inspectFresh(fresh, error)) {
        error = "drift gate: fresh inspection failed: " + error;
        return false;
    }
    if (fresh.selections != expected.selections ||
        fresh.qualitySlotState != expected.qualitySlotState ||
        fresh.historySlotState != expected.historySlotState ||
        fresh.historyInitialSlotState != expected.historyInitialSlotState ||
        fresh.foreignQualityProducer != expected.foreignQualityProducer) {
        error =
            "drift detected: the physical password topology no longer "
            "matches the proven intermediate state of this transition "
            "(the stale plan is aborted; a retry starts a fresh "
            "transition)";
        return false;
    }
    std::string stateError;
    if (!requireUsableCurrentState(fresh, stateError)) {
        error = "drift gate: " + stateError;
        return false;
    }
    return true;
}

PamPasswordTopologyClass
PamPasswordTopologyTransitionExecutor::desiredTopologyClass(
    const PamPasswordTopologyPlan& plan, bool foreignProducer) {
    if (plan.wantFicHistoryInitial) {
        return PamPasswordTopologyClass::FicHistoryInitial;
    }
    if (plan.wantFicHistoryConsumer) {
        return foreignProducer
            ? PamPasswordTopologyClass::ForeignQualityPlusFicHistory
            : PamPasswordTopologyClass::FicQualityPlusFicHistory;
    }
    if (plan.wantFicQuality) {
        return PamPasswordTopologyClass::FicQuality;
    }
    return foreignProducer ? PamPasswordTopologyClass::ForeignQuality
                           : PamPasswordTopologyClass::None;
}

bool PamPasswordTopologyTransitionExecutor::executeAction(
    const PamPasswordPlanAction& action, ActionAttempt& attempt,
    std::string& error) {
    attempt = {};
    attempt.kind = action.kind;
    const char* profileId = action.profileId();
    const char* flag = isAttach(action.kind) ? "--enable" : "--disable";

    if (isAttach(action.kind)) {
        // Attach ordering (C2 invariant): write the Active slot FIRST,
        // prove it durably (journal Prepared -> Applied inside the
        // writer), and only then select the profile. The unsafe window
        // "selected high-priority profile + Neutral slot" can never exist
        // on this path.
        PamManagedPasswordSlotWriter& writer =
            action.kind == PamPasswordPlanActionKind::AttachFicQuality
            ? qualityWriter_
            : historyWriter_;
        const ManagedPasswordSlotRole role =
            action.kind == PamPasswordPlanActionKind::AttachFicQuality
            ? ManagedPasswordSlotRole::Quality
            : (action.kind ==
                    PamPasswordPlanActionKind::AttachFicHistoryInitial
                ? ManagedPasswordSlotRole::HistoryInitial
                : ManagedPasswordSlotRole::HistoryNormal);
        PamManagedPasswordSlotActivationResult activation;
        const bool activated = writer.activateC2Slot(
            role, options_.historyOptions, activation, error);
        // Partial-state propagation: the activation may fail AFTER the
        // physical slot write persisted (e.g. journal Prepared -> Applied
        // commit failure). In that case the result carries the exact
        // outstanding mutation id that compensation must neutralize,
        // regardless of the bool return. A fully (internally) compensated
        // failure reports 0: no caller-side compensation is needed or
        // allowed.
        attempt.slotMutationId = activation.mutationId;
        if (!activated) {
            return false;
        }
        // The native call result is NEVER trusted alone: the resulting
        // physical state is freshly inspected by the transition loop.
        attempt.nativeAttempted = true;
        std::string nativeError;
        runPamAuthUpdateOne(flag, profileId, nativeError);
        return true;
    }

    // Detach ordering: remove the selection FIRST, prove the profile
    // physically detached, and only then write the Neutral slot. The slot
    // is never neutralized while the profile is selected.
    attempt.nativeAttempted = true;
    runPamAuthUpdateOne(flag, profileId, error);
    PamPasswordTopologySnapshot fresh;
    if (!inspectFresh(fresh, error)) {
        return false;
    }
    const bool stillSelected =
        selectionFlagFor(fresh.selections, action.kind);
    bool includeStillPresent = false;
    switch (action.kind) {
    case PamPasswordPlanActionKind::DetachFicQuality:
        includeStillPresent = fresh.generated.qualityInclude;
        break;
    case PamPasswordPlanActionKind::DetachFicHistoryConsumer:
        includeStillPresent = fresh.generated.historyInclude;
        break;
    case PamPasswordPlanActionKind::DetachFicHistoryInitial:
        includeStillPresent = fresh.generated.historyInitialInclude;
        break;
    default:
        break;
    }
    if (stillSelected || includeStillPresent) {
        error = std::string("the detach of ") + profileId +
            " is not proven: the profile selection or its generated "
            "include is still present after the native mutation";
        return false;
    }
    attempt.selectionRemovedProven = true;
    // Neutralize the FIC-owned slot (exact Applied provenance gate inside
    // the writer).
    PamManagedPasswordSlotWriter& writer =
        action.kind == PamPasswordPlanActionKind::DetachFicQuality
        ? qualityWriter_
        : historyWriter_;
    const ManagedPasswordSlotRole role =
        action.kind == PamPasswordPlanActionKind::DetachFicQuality
        ? ManagedPasswordSlotRole::Quality
        : (action.kind ==
                PamPasswordPlanActionKind::DetachFicHistoryInitial
            ? ManagedPasswordSlotRole::HistoryInitial
            : ManagedPasswordSlotRole::HistoryNormal);
    PamManagedPasswordSlotActivationResult deactivation;
    if (!writer.deactivateC2Slot(role, deactivation, error)) {
        return false;
    }
    return true;
}

bool PamPasswordTopologyTransitionExecutor::compensateAttempt(
    const ActionAttempt& attempt, bool& compensatedChanged,
    std::string& error) {
    // Semantic inverse of one action. Fail-fast: the first failed or
    // unproven inverse mutation stops the caller's compensation loop.
    if (isAttach(attempt.kind)) {
        const char* profileId = nullptr;
        const ManagedPasswordSlotRole role =
            [&]() -> ManagedPasswordSlotRole {
            switch (attempt.kind) {
            case PamPasswordPlanActionKind::AttachFicQuality:
                profileId = kFicPasswordQualityHookProfileId;
                return ManagedPasswordSlotRole::Quality;
            case PamPasswordPlanActionKind::AttachFicHistoryConsumer:
                profileId = kFicPasswordHistoryHookProfileId;
                return ManagedPasswordSlotRole::HistoryNormal;
            case PamPasswordPlanActionKind::AttachFicHistoryInitial:
                profileId = kFicPasswordHistoryInitialHookProfileId;
                return ManagedPasswordSlotRole::HistoryInitial;
            default:
                profileId = kFicPasswordQualityHookProfileId;
                return ManagedPasswordSlotRole::Quality;
            }
        }();
        if (attempt.nativeAttempted) {
            // The native mutation is ambiguous by definition: the
            // resulting state decides, never the exit status.
            PamPasswordTopologySnapshot fresh;
            if (!inspectFresh(fresh, error)) {
                return false;
            }
            if (selectionFlagFor(fresh.selections, attempt.kind)) {
                if (!runPamAuthUpdateOne("--disable", profileId, error)) {
                    error = "compensation disable of " +
                        std::string(profileId) + " failed: " + error;
                    return false;
                }
                PamPasswordTopologySnapshot after;
                if (!inspectFresh(after, error) ||
                    selectionFlagFor(after.selections, attempt.kind)) {
                    error =
                        "compensation could not prove the absence of " +
                        std::string(profileId);
                    return false;
                }
            }
        }
        if (attempt.slotMutationId != 0) {
            bool changed = false;
            PamManagedPasswordSlotWriter& writer =
                attempt.kind ==
                    PamPasswordPlanActionKind::AttachFicQuality
                ? qualityWriter_
                : historyWriter_;
            if (!writer.compensateC2ActiveSlot(
                    role, attempt.slotMutationId, changed, error)) {
                return false;
            }
            compensatedChanged = compensatedChanged || changed;
        }
        return true;
    }

    // Detach inverse: re-attach the FIC-owned identity (slot Active
    // first, then the native selection), matching the attach ordering.
    if (!attempt.selectionRemovedProven) {
        return true;
    }
    const char* profileId = nullptr;
    const ManagedPasswordSlotRole role =
        [&]() -> ManagedPasswordSlotRole {
        switch (attempt.kind) {
        case PamPasswordPlanActionKind::DetachFicQuality:
            profileId = kFicPasswordQualityHookProfileId;
            return ManagedPasswordSlotRole::Quality;
        case PamPasswordPlanActionKind::DetachFicHistoryConsumer:
            profileId = kFicPasswordHistoryHookProfileId;
            return ManagedPasswordSlotRole::HistoryNormal;
        case PamPasswordPlanActionKind::DetachFicHistoryInitial:
            profileId = kFicPasswordHistoryInitialHookProfileId;
            return ManagedPasswordSlotRole::HistoryInitial;
        default:
            profileId = kFicPasswordQualityHookProfileId;
            return ManagedPasswordSlotRole::Quality;
        }
    }();
    PamManagedPasswordSlotWriter& writer =
        attempt.kind == PamPasswordPlanActionKind::DetachFicQuality
        ? qualityWriter_
        : historyWriter_;
    PamManagedPasswordSlotActivationResult activation;
    const bool activated = writer.activateC2Slot(
        role, options_.historyOptions, activation, error);
    if (!activated) {
        // F12 hardening: the inverse re-attach itself can fail AFTER the
        // physical slot write persisted (the known partial activation
        // path). Such a failure carries the exact outstanding mutation
        // id; stopping here without cleanup would leave a NEW orphaned
        // Active slot + Prepared record behind on top of the failed
        // restoration.
        compensatedChanged =
            compensatedChanged || activation.changedSystemState;
        if (activation.mutationId == 0) {
            // No caller-compensatable outstanding state remains: the
            // writer fully compensated internally (or nothing was
            // mutated). Fail fast.
            error = "inverse re-attach of " + std::string(profileId) +
                " failed without an outstanding partial activation: " +
                error;
            return false;
        }
        // Exact-id local cleanup (no recursive compensation engine):
        // neutralize the partial slot activation before the fail-fast
        // STOP so the compensation does not create new orphaned state.
        bool cleaned = false;
        std::string cleanupError;
        const bool cleanedOk = writer.compensateC2ActiveSlot(
            role, activation.mutationId, cleaned, cleanupError);
        compensatedChanged = compensatedChanged || (cleanedOk && cleaned);
        if (cleanedOk) {
            error = "inverse re-attach of " + std::string(profileId) +
                " failed (" + error +
                "); its partial slot activation was cleaned";
        } else {
            error = "inverse re-attach of " + std::string(profileId) +
                " failed (" + error +
                "); partial inverse activation could NOT be cleaned: " +
                cleanupError;
        }
        return false;
    }
    compensatedChanged =
        compensatedChanged || activation.changedSystemState;
    if (!runPamAuthUpdateOne("--enable", profileId, error)) {
        error = "compensation enable of " + std::string(profileId) +
            " failed: " + error;
        return false;
    }
    PamPasswordTopologySnapshot after;
    if (!inspectFresh(after, error) ||
        !selectionFlagFor(after.selections, attempt.kind)) {
        error = "compensation could not prove the re-selection of " +
            std::string(profileId);
        return false;
    }
    return true;
}

bool PamPasswordTopologyTransitionExecutor::transition(
    bool qualityRequested, bool historyRequested,
    PamPasswordTransitionResult& result, std::string& error) {
    result = {};

    // 1. Fresh inspection of the current physical topology.
    PamPasswordTopologySnapshot pre;
    if (!inspectFresh(pre, error)) {
        error = "transition inspection failed: " + error;
        return false;
    }
    if (!requireUsableCurrentState(pre, error)) {
        return false;
    }
    result.topologyBefore = pre.classification.topologyClass;

    // 2. The planner is the ONLY semantic decision source.
    const PamPasswordTopologyPlan plan = planPamPasswordTopology(
        pre.topology, qualityRequested, historyRequested, pre.ownership);
    if (!plan.success) {
        error = "topology planning failed closed: " + plan.error;
        return false;
    }
    // F9: physically selected but unowned FIC identities are never
    // destructively modified.
    if (!plan.unownedSelectionsPreserved.empty()) {
        std::string joined;
        for (const std::string& identifier :
             plan.unownedSelectionsPreserved) {
            if (!joined.empty()) {
                joined += ", ";
            }
            joined += identifier;
        }
        error =
            "fail closed: physically selected FIC password profiles lack "
            "journal ownership provenance and will not be modified: " +
            joined;
        return false;
    }

    // 3. No-op transitions still require a fresh desired-state proof
    // (a foreign producer already satisfying the request is a legitimate
    // no-op; anything else fails closed).
    if (plan.actions.empty()) {
        PamPasswordTopologySnapshot fresh;
        if (!inspectFresh(fresh, error)) {
            return false;
        }
        if (!requireUsableCurrentState(fresh, error)) {
            return false;
        }
        const PamPasswordTopologyClass desired =
            desiredTopologyClass(plan, fresh.foreignQualityProducer);
        if (fresh.classification.topologyClass != desired) {
            error =
                "no-op transition refused (fail closed): the physical "
                "topology does not prove the desired semantic state";
            return false;
        }
        result.topologyAfter = fresh.classification.topologyClass;
        result.success = true;
        error.clear();
        return true;
    }

    // 4. Ordered action execution with per-action immediate proofs.
    PamPasswordTopologySnapshot expected = pre;
    std::vector<ActionAttempt> proven;
    auto failWithCompensation = [&](const std::string& failure,
                                    const ActionAttempt* pendingAttempt) {
        result.compensated = true;
        bool compensatedChanged = false;
        std::string compensationError;
        if (pendingAttempt != nullptr &&
            !compensateAttempt(
                *pendingAttempt, compensatedChanged, compensationError)) {
            // Fail-fast (F6/F7): STOP on the first unproven inverse
            // mutation; never mutate further on an unknown topology.
            result.changedSystemState = true;
            error = failure +
                "; CRITICAL: C2 PAM topology NOT proven restored; "
                "compensation stopped: " +
                compensationError;
            return false;
        }
        for (std::size_t index = proven.size(); index > 0; --index) {
            if (!compensateAttempt(
                    proven[index - 1], compensatedChanged,
                    compensationError)) {
                result.changedSystemState = true;
                error = failure +
                    "; CRITICAL: C2 PAM topology NOT proven restored; "
                    "compensation stopped: " +
                    compensationError;
                return false;
            }
        }
        // Final proof of the pre-transition state.
        PamPasswordTopologySnapshot restored;
        if (!inspectFresh(restored, error)) {
            result.changedSystemState = true;
            error = failure +
                "; CRITICAL: C2 PAM topology NOT proven restored; the "
                "restored-state inspection failed: " +
                error;
            return false;
        }
        if (restored.selections != pre.selections ||
            restored.qualitySlotState != pre.qualitySlotState ||
            restored.historySlotState != pre.historySlotState ||
            restored.historyInitialSlotState !=
                pre.historyInitialSlotState ||
            // Foreign state is preserved, never claimed: foreign
            // disappearing fails the restoration; a foreign producer that
            // APPEARED during the transition is left untouched (the FIC
            // state comparison above already proves the FIC-owned state).
            (pre.foreignQualityProducer &&
                !restored.foreignQualityProducer) ||
            !(restored.ownership == pre.ownership)) {
            result.changedSystemState = true;
            error = failure +
                "; CRITICAL: C2 PAM topology NOT proven restored: the "
                "compensated state diverges from the proven "
                "pre-transition state";
            return false;
        }
        std::string restoredStateError;
        if (!requireUsableCurrentState(restored, restoredStateError)) {
            result.changedSystemState = true;
            error = failure +
                "; CRITICAL: C2 PAM topology NOT proven restored: " +
                restoredStateError;
            return false;
        }
        result.compensatedStateProven = true;
        result.topologyAfter = restored.classification.topologyClass;
        error =
            failure + "; compensated to the proven pre-transition state";
        return false;
    };

    for (const PamPasswordPlanAction& action : plan.actions) {
        // Drift gate: the physical state must still match the proven
        // intermediate state; foreign drift aborts the stale plan
        // (one plan per transition — no transparent re-planning).
        if (!driftGate(expected, error)) {
            return failWithCompensation(
                "transition aborted before action " +
                    std::string(action.profileId()),
                nullptr);
        }
        ActionAttempt attempt;
        if (!executeAction(action, attempt, error)) {
            return failWithCompensation(
                "action " + std::string(action.profileId()) +
                    " failed: " + error,
                &attempt);
        }
        result.changedSystemState = true;
        // Immediate resulting-state proof of the expected intermediate
        // state (the same comparison doubles as the drift detection for
        // the NEXT action).
        switch (action.kind) {
        case PamPasswordPlanActionKind::AttachFicQuality:
            expected.selections.ficQualitySelected = true;
            expected.qualitySlotState = ManagedPasswordSlotState::Active;
            expected.qualitySlotMutationId = attempt.slotMutationId;
            break;
        case PamPasswordPlanActionKind::AttachFicHistoryInitial:
            expected.selections.ficHistoryInitialSelected = true;
            expected.historyInitialSlotState =
                ManagedPasswordSlotState::Active;
            expected.historyInitialSlotMutationId = attempt.slotMutationId;
            break;
        case PamPasswordPlanActionKind::AttachFicHistoryConsumer:
            expected.selections.ficHistorySelected = true;
            expected.historySlotState = ManagedPasswordSlotState::Active;
            expected.historySlotMutationId = attempt.slotMutationId;
            break;
        case PamPasswordPlanActionKind::DetachFicQuality:
            expected.selections.ficQualitySelected = false;
            expected.qualitySlotState = ManagedPasswordSlotState::Neutral;
            expected.qualitySlotMutationId = 0;
            break;
        case PamPasswordPlanActionKind::DetachFicHistoryInitial:
            expected.selections.ficHistoryInitialSelected = false;
            expected.historyInitialSlotState =
                ManagedPasswordSlotState::Neutral;
            expected.historyInitialSlotMutationId = 0;
            break;
        case PamPasswordPlanActionKind::DetachFicHistoryConsumer:
            expected.selections.ficHistorySelected = false;
            expected.historySlotState = ManagedPasswordSlotState::Neutral;
            expected.historySlotMutationId = 0;
            break;
        }
        if (!driftGate(expected, error)) {
            return failWithCompensation(
                "the resulting-state proof of action " +
                    std::string(action.profileId()) + " failed: " + error,
                &attempt);
        }
        proven.push_back(attempt);
        result.executedActions.push_back(action.profileId());
    }

    // 5. Final full three-profile topology proof (Applied).
    PamPasswordTopologySnapshot final;
    if (!inspectFresh(final, error)) {
        return failWithCompensation(
            "the final topology inspection failed: " + error, nullptr);
    }
    if (!requireUsableCurrentState(final, error)) {
        return failWithCompensation(
            "the final topology proof failed: " + error, nullptr);
    }
    const PamPasswordTopologyClass desired =
        desiredTopologyClass(plan, final.foreignQualityProducer);
    if (final.classification.topologyClass != desired) {
        return failWithCompensation(
            "the final topology class does not match the desired "
            "semantic state",
            nullptr);
    }
    result.topologyAfter = final.classification.topologyClass;
    result.success = true;
    error.clear();
    return true;
}

} // namespace fic::identity::pam
