#include "modules/identity_access/pam/PamPasswordPackageRelease.h"

#include <fic/core/process/ExclusivePidLock.h>

#include <algorithm>
#include <memory>
#include <utility>

namespace fic::identity::pam {

PamPasswordPackageRelease::PamPasswordPackageRelease(
    fic::rollback::MutationJournal& journal,
    const fic::platform::PlatformExecutableResolver& executables,
    Options options)
    : journal_(journal),
      options_(std::move(options)),
      // Same construction shape and path normalization as the production
      // coordinator: the executor owns ONE transition semantic and never
      // trusts an empty path against the process working directory.
      executor_(journal_, executables, options_.executorOptions,
                options_.configDirectory, options_.stateDirectory),
      qualityWriter_(
          options_.configDirectory.empty()
              ? std::filesystem::path("/etc/pam.d")
              : options_.configDirectory,
          journal_, PamManagedPasswordDomain::Quality),
      historyWriter_(
          options_.configDirectory.empty()
              ? std::filesystem::path("/etc/pam.d")
              : options_.configDirectory,
          journal_, PamManagedPasswordDomain::History) {}

void PamPasswordPackageRelease::setQualitySlotFaultHooksForTests(
    SlotFaultHook beforeWrite, SlotFaultHook afterWrite) {
    // Both the executor's domain writer AND this object's recovery writer
    // share the fault seam so release-stage recovery is faultable too.
    executor_.setQualitySlotFaultHooksForTests(beforeWrite, afterWrite);
    qualityWriter_.setBeforeSlotWriteHookForTests(beforeWrite);
    qualityWriter_.setAfterSlotWriteHookForTests(afterWrite);
}

void PamPasswordPackageRelease::setHistorySlotFaultHooksForTests(
    SlotFaultHook beforeWrite, SlotFaultHook afterWrite) {
    executor_.setHistorySlotFaultHooksForTests(beforeWrite, afterWrite);
    historyWriter_.setBeforeSlotWriteHookForTests(beforeWrite);
    historyWriter_.setAfterSlotWriteHookForTests(afterWrite);
}

void PamPasswordPackageRelease::
    setQualityJournalCompletionFaultHookForTests(
        JournalCompletionFaultHook hook) {
    executor_.setQualityJournalCompletionFaultHookForTests(hook);
    qualityWriter_.setJournalCompletionFaultHookForTests(hook);
}

void PamPasswordPackageRelease::
    setHistoryJournalCompletionFaultHookForTests(
        JournalCompletionFaultHook hook) {
    executor_.setHistoryJournalCompletionFaultHookForTests(hook);
    historyWriter_.setJournalCompletionFaultHookForTests(hook);
}

void PamPasswordPackageRelease::setHistoryC2CompensationFaultHookForTests(
    C2CompensationFaultHook hook) {
    executor_.setHistoryC2CompensationFaultHookForTests(hook);
    historyWriter_.setC2CompensationFaultHookForTests(hook);
}

auto PamPasswordPackageRelease::identityViews(
    const PamPasswordTopologySnapshot& snapshot) const
    -> std::vector<IdentityView> {
    return {
        {kFicPasswordQualityHookProfileId,
         snapshot.selections.ficQualitySelected,
         snapshot.ownership.ficQualityOwned,
         snapshot.ownership.ficQualityPrepared,
         snapshot.qualitySlotState, snapshot.qualitySlotMutationId,
         ManagedPasswordSlotRole::Quality},
        {kFicPasswordHistoryHookProfileId,
         snapshot.selections.ficHistorySelected,
         snapshot.ownership.ficHistoryOwned,
         snapshot.ownership.ficHistoryPrepared,
         snapshot.historySlotState, snapshot.historySlotMutationId,
         ManagedPasswordSlotRole::HistoryNormal},
        {kFicPasswordHistoryInitialHookProfileId,
         snapshot.selections.ficHistoryInitialSelected,
         snapshot.ownership.ficHistoryInitialOwned,
         snapshot.ownership.ficHistoryInitialPrepared,
         snapshot.historyInitialSlotState,
         snapshot.historyInitialSlotMutationId,
         ManagedPasswordSlotRole::HistoryInitial},
    };
}

bool PamPasswordPackageRelease::inspectAndCheckStructure(
    PamPasswordTopologySnapshot& snapshot,
    std::vector<IdentityView>& leftovers, std::string& error) {
    PamPasswordStateInspectionOptions inspection;
    inspection.configDirectory = options_.configDirectory;
    inspection.stateDirectory = options_.stateDirectory;
    if (!inspectPamPasswordTopology(inspection, journal_, snapshot,
                                    error)) {
        error = "journal provenance unavailable: the current physical "
                "password topology could not be inspected: " +
            error;
        return false;
    }
    if (!snapshot.coherenceError.empty()) {
        error = "unsafe topology: the current physical password topology "
                "is incoherent (fail closed): " +
            snapshot.coherenceError;
        return false;
    }
    const std::vector<IdentityView> identities = identityViews(snapshot);
    if (snapshot.selections.ficHistorySelected &&
        snapshot.selections.ficHistoryInitialSelected) {
        error =
            "ambiguous topology: both FIC history variants (consumer and "
            "initial producer) are selected; package removal cannot "
            "safely continue";
        return false;
    }
    for (const IdentityView& identity : identities) {
        if (identity.selected && !identity.owned) {
            error = std::string("selected FIC PAM profile ") +
                identity.profileId +
                " is not proven FIC-owned; package removal cannot safely "
                "continue";
            return false;
        }
        if (!identity.selected && identity.owned) {
            error = std::string("incoherent topology: ") +
                identity.profileId +
                " is FIC-owned by journal provenance but not selected; "
                "package removal cannot safely continue";
            return false;
        }
        if (!identity.selected && identity.prepared &&
            identity.slotState == ManagedPasswordSlotState::Active) {
            // Exact-id Prepared crash-leftover (crash between the slot
            // activation and the native selection). Recoverable through
            // the production compensation primitive in the release stage.
            leftovers.push_back(identity);
        }
    }
    return true;
}

bool PamPasswordPackageRelease::checkSafetyAndSemantics(
    const PamPasswordTopologySnapshot& snapshot,
    const std::vector<IdentityView>& leftovers, std::string& error) {
    // Virtually recover the prepared leftovers in memory: the release
    // stage neutralizes them physically before the transition, so the
    // eligibility decision must judge the state that the release stage
    // will actually establish.
    PamPasswordTopologySnapshot virtualState = snapshot;
    for (const IdentityView& leftover : leftovers) {
        switch (leftover.role) {
        case ManagedPasswordSlotRole::Quality:
            virtualState.qualitySlotState =
                ManagedPasswordSlotState::Neutral;
            virtualState.qualitySlotMutationId = 0;
            virtualState.ownership.ficQualityPrepared = false;
            break;
        case ManagedPasswordSlotRole::HistoryNormal:
            virtualState.historySlotState =
                ManagedPasswordSlotState::Neutral;
            virtualState.historySlotMutationId = 0;
            virtualState.ownership.ficHistoryPrepared = false;
            break;
        case ManagedPasswordSlotRole::HistoryInitial:
            virtualState.historyInitialSlotState =
                ManagedPasswordSlotState::Neutral;
            virtualState.historyInitialSlotMutationId = 0;
            virtualState.ownership.ficHistoryInitialPrepared = false;
            break;
        }
    }
    // Recompute classification and C2 safety for the virtually recovered
    // state: the snapshot verdicts were computed on the physical state
    // with the orphaned Active leftovers, which the release stage will
    // have neutralized before this gate matters.
    virtualState.classification =
        classifyPamPasswordTopology(virtualState.topology);
    const PamPasswordC2SlotStates virtualSlots{
        virtualState.qualitySlotState, virtualState.historySlotState,
        virtualState.historyInitialSlotState};
    virtualState.safety = evaluatePamPasswordC2SelectionSafety(
        virtualState.selections, virtualSlots,
        virtualState.foreignQualityProducer);
    // The foreign-added-during-FIC state is deliberately NOT attach-safe
    // (classification.valid == false), but the ownership-aware release
    // path (detach-only plan) must be able to run from it — the same
    // allowance the runtime disable path has.
    const bool usableClass =
        virtualState.classification.valid ||
        virtualState.classification.topologyClass ==
            PamPasswordTopologyClass::ForeignQualityPlusFicQuality;
    if (!usableClass) {
        error = "unsafe topology: the current physical password topology "
                "is not releasable (fail closed): " +
            virtualState.classification.detail;
        return false;
    }
    if (!virtualState.safety.safe) {
        error = "unsafe topology: the current physical password topology "
                "is not C2-safe (fail closed): " +
            virtualState.safety.reason;
        return false;
    }
    std::string semanticsError;
    if (!provePamPasswordTopologySemantics(
            virtualState, semanticsError)) {
        error = "unsafe topology: the current physical password topology "
                "failed the semantic proof (fail closed): " +
            semanticsError;
        return false;
    }
    return true;
}

bool PamPasswordPackageRelease::recoverCrashLeftovers(
    const std::vector<IdentityView>& leftovers, Report& report,
    std::string& error) {
    for (const IdentityView& leftover : leftovers) {
        PamManagedPasswordSlotWriter& writer =
            leftover.role == ManagedPasswordSlotRole::Quality
            ? qualityWriter_
            : historyWriter_;
        bool changed = false;
        // Exact-id production compensation primitive: neutralizes ONLY
        // the canonical Active slot whose marker carries the EXACT
        // Prepared record id and discards that record; every other state
        // fails closed inside the writer.
        if (!writer.compensateC2ActiveSlot(
                leftover.role, leftover.slotMutationId, changed, error)) {
            error = "the exact-id Prepared crash-leftover of " +
                std::string(leftover.profileId) +
                " could not be recovered to the safe neutral state (fail "
                "closed): " +
                error;
            return false;
        }
        report.recoveredCrashLeftovers.push_back(leftover.profileId);
    }
    if (leftovers.empty()) {
        return true;
    }
    // Fresh proof of the recovered state, scoped to the identities this
    // recovery actually touched: every recovered leftover must now be
    // canonical Neutral with no Prepared binding and no ownership left.
    // Unrelated valid Applied/owned identities (e.g. still-owned quality
    // in a mixed Owned+Prepared release) are NOT required to be Neutral
    // here; they are released by the normal transition(false, false) and
    // proven by proveFinalState().
    PamPasswordTopologySnapshot recovered;
    std::vector<IdentityView> remainingLeftovers;
    if (!inspectAndCheckStructure(recovered, remainingLeftovers, error)) {
        error = "the recovered post-crash-leftover state failed the fresh "
                "structural proof: " +
            error;
        return false;
    }
    const std::vector<IdentityView> recoveredViews =
        identityViews(recovered);
    for (const IdentityView& leftover : leftovers) {
        const IdentityView* current = nullptr;
        for (const IdentityView& view : recoveredViews) {
            if (view.role == leftover.role) {
                current = &view;
                break;
            }
        }
        if (current == nullptr) {
            error = std::string("the recovered identity ") +
                leftover.profileId +
                " is missing from the fresh post-recovery inspection "
                "(fail closed)";
            return false;
        }
        if (current->selected || current->owned || current->prepared ||
            current->slotState != ManagedPasswordSlotState::Neutral ||
            current->slotMutationId != 0) {
            error = std::string("the managed password slot of ") +
                current->profileId +
                " is not canonical Neutral without any Prepared binding "
                "after the crash-leftover recovery (fail closed)";
            return false;
        }
    }
    // Full structural/safety/semantic gate of the fresh remaining state:
    // once the Prepared leftovers are recovered, the remaining topology
    // (e.g. still-owned FicQuality) must be a valid releasable state on
    // its own; the package-release transition then neutralizes it through
    // the normal planner/executor path (no manual neutralization here).
    if (!checkSafetyAndSemantics(recovered, remainingLeftovers, error)) {
        error = "the remaining topology after the crash-leftover recovery "
                "is not a valid releasable state (fail closed): " +
            error;
        return false;
    }
    return true;
}

bool PamPasswordPackageRelease::proveFinalState(
    const PamPasswordTopologySnapshot& pre, Report& report,
    std::string& error) {
    PamPasswordTopologySnapshot finalSnapshot;
    std::vector<IdentityView> leftovers;
    if (!inspectAndCheckStructure(finalSnapshot, leftovers, error)) {
        error = "the final topology proof failed: " + error;
        return false;
    }
    if (!leftovers.empty()) {
        error = "the final topology proof failed: an exact-id Prepared "
                "crash-leftover is still present (fail closed)";
        return false;
    }
    for (const IdentityView& identity : identityViews(finalSnapshot)) {
        if (identity.selected) {
            error = std::string("the final topology proof failed: the ") +
                identity.profileId +
                " selection is still present after the package release";
            return false;
        }
        if (identity.slotState != ManagedPasswordSlotState::Neutral) {
            error = std::string("the final topology proof failed: the ") +
                identity.profileId +
                " managed slot is not canonical Neutral after the "
                "package release";
            return false;
        }
    }
    // No FIC generated include may remain (include/selection coherence is
    // proven above; the explicit include absence keeps the proof honest
    // against future inspection changes).
    if (finalSnapshot.generated.qualityInclude ||
        finalSnapshot.generated.historyInclude ||
        finalSnapshot.generated.historyInitialInclude) {
        error = "the final topology proof failed: a FIC managed slot "
                "include is still present in the generated password "
                "stack";
        return false;
    }
    // Foreign preservation: a producer that existed before the release
    // must still exist; the release never removes foreign state.
    if (pre.foreignQualityProducer &&
        !finalSnapshot.foreignQualityProducer) {
        error = "the final topology proof failed: the foreign pwquality "
                "producer disappeared during the package release (fail "
                "closed)";
        return false;
    }
    const bool finalClassOk =
        finalSnapshot.classification.topologyClass ==
            PamPasswordTopologyClass::None ||
        finalSnapshot.classification.topologyClass ==
            PamPasswordTopologyClass::ForeignQuality;
    if (!finalClassOk) {
        error = "the final topology proof failed: the resulting semantic "
                "topology is neither None nor ForeignQuality";
        return false;
    }
    if (!checkSafetyAndSemantics(finalSnapshot, {}, error)) {
        error = "the final topology proof failed: " + error;
        return false;
    }
    report.topologyAfter = finalSnapshot.classification.topologyClass;
    report.foreignProducerPresent = finalSnapshot.foreignQualityProducer;
    return true;
}

bool PamPasswordPackageRelease::run(
    Mode mode, Report& report, std::string& error) {
    report = {};

    // 1. Fresh inspection + structural gate. In preflight this is the
    // whole read-only decision; in release it decides the crash-leftover
    // recovery scope BEFORE any mutation.
    PamPasswordTopologySnapshot snapshot;
    std::vector<IdentityView> leftovers;
    if (!inspectAndCheckStructure(snapshot, leftovers, error)) {
        return false;
    }
    if (!checkSafetyAndSemantics(snapshot, leftovers, error)) {
        return false;
    }
    report.topologyBefore = snapshot.classification.topologyClass;
    report.foreignProducerPresent = snapshot.foreignQualityProducer;

    if (mode == Mode::Preflight) {
        // Strictly read-only: no lock, no recovery, no transition. The
        // prepared leftovers are reported as recoverable by the release
        // stage; the eligibility verdict already judged the virtually
        // recovered state.
        report.topologyAfter = PamPasswordTopologyClass::None;
        return true;
    }

    // 2. Exclusive cross-process mutation serialization (Stage B). The
    // runtime daemon is stopped by the caller BEFORE this stage; the lock
    // serializes against other local maintenance invocations.
    std::unique_ptr<ExclusivePidLock> lock;
    if (!options_.lockFilePath.empty()) {
        // The daemon owns the runtime dir while it runs, but the package
        // prerm runs this stage with the daemon stopped (the runtime dir
        // may legitimately not exist yet). Create the lock file parent so
        // the lock acquisition below operates on a real path.
        std::error_code lockDirError;
        std::filesystem::create_directories(
            options_.lockFilePath.parent_path(), lockDirError);
        lock = std::make_unique<ExclusivePidLock>(
            options_.lockFilePath.string(), options_.lockDebugLogPath,
            /*enableDebug=*/false);
        if (!lock->acquire()) {
            error = "another FIC password package-release mutation is "
                    "already in progress (exclusive lock busy): " +
                options_.lockFilePath.string();
            return false;
        }
    }

    // 3. Exact-id Prepared crash-leftover recovery (production
    // compensation primitive only), then a fresh structural gate.
    if (!recoverCrashLeftovers(leftovers, report, error)) {
        return false;
    }

    // 4. ONE package-release transition through the production executor:
    // fresh inspection inside, planner-ordered detaches (history variant
    // before its producer), one profile per native mutation, per-action
    // proofs, C2 compensation on failure. The desired state is the
    // package lifecycle target and never the configuration intent.
    PamPasswordTransitionResult transitionResult;
    if (!executor_.transition(
            /*qualityRequested=*/false, /*historyRequested=*/false,
            transitionResult, error)) {
        report.changedSystemState = transitionResult.changedSystemState;
        report.compensated = transitionResult.compensated;
        report.compensatedStateProven =
            transitionResult.compensatedStateProven;
        std::string classification =
            "package password release transition failed";
        if (transitionResult.compensated) {
            classification +=
                transitionResult.compensatedStateProven
                ? " (attempted changes compensated; pre-release topology "
                  "proven restored; a retry may succeed)"
                : "; CRITICAL: C2 password topology NOT proven restored; "
                  "compensation stopped; package removal must stay "
                  "blocked until explicit recovery";
        } else if (transitionResult.changedSystemState) {
            classification += " (partial mutation may be installed)";
        }
        error = classification + ": " + error;
        return false;
    }
    report.changedSystemState = transitionResult.changedSystemState;
    report.detachedIdentities = transitionResult.executedActions;

    // 5. Independent final proof of the package-release target state.
    if (!proveFinalState(snapshot, report, error)) {
        return false;
    }
    error.clear();
    return true;
}

} // namespace fic::identity::pam