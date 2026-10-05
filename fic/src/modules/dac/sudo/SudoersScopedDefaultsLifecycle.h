#ifndef FIC_SUDOERSSCOPEDDEFAULTSLIFECYCLE_H
#define FIC_SUDOERSSCOPEDDEFAULTSLIFECYCLE_H



#include "modules/dac/sudo/SudoersScopedDefaultsTransaction.h"
#include "rollback/MutationRecord.h"

#include <functional>
#include <string>
#include <vector>

using fic::rollback::MutationBackend;
using fic::rollback::MutationId;
using fic::rollback::MutationRecord;
using fic::rollback::MutationStatus;
using fic::rollback::UndoAction;
using fic::rollback::UndoReleaseSudoScopedDefaults;

// Production ORCHESTRATION for the SUDO scoped-Defaults blocker.
//
// The transaction component owns the filesystem mechanics; this component owns
// the JOURNAL state machine around it: ownership collection, Prepared
// recovery, planning, prepare -> mutate -> commit/discard, and the single
// invariant that decides the fate of a Prepared record.
//
// The policy class is deliberately thin (resolve options, take the shared
// mutation lock, call reconcile(), log), and the tests drive THIS component
// directly, so crash-recovery and partial-failure paths are exercised through
// the production code path instead of a hand-copied imitation of it.
namespace fic::sudoers {

// The journal operations the lifecycle needs. Injected so the lifecycle stays
// testable and free of any daemon singleton.
struct ScopedDefaultsJournalAccess {
    // All ACTIVE records of this policy (any resource).
    std::function<std::vector<MutationRecord>(const PolicyRef&)> activeRecords;
    std::function<bool(const PolicyRef&, const std::string& resource,
                       const UndoAction&, MutationId&, std::string&)>
        prepare;
    std::function<bool(MutationId, std::string&)> commit;
    std::function<bool(MutationId, std::string&)> discard;
    // Normalizes an unresolved refresh Prepared(previous=P,target=P+F) back to
    // Applied(target=P) on the SAME id. Required whenever the filesystem is
    // proven to hold exactly P: a plain discard would orphan the physical
    // wrappers of P.
    std::function<bool(MutationId,
                       const std::vector<SudoScopedDefaultsWrapperProof>&,
                       std::string&)>
        normalizePreparedToPrevious;
    // Test-only seam between a successful mechanical compensation and the final
    // snapshot-bound previous-resolution proof.
    std::function<void()> afterPreparedCompensation;
    // Test-only seam immediately BEFORE the final @includedir topology guard of
    // a journal transition (commit / normalize / discard). Lets a test change
    // the directory membership in the exact window the guard protects.
    std::function<void()> beforeFinalTopologyGuard;
    // Test-only seam immediately BEFORE the no-op topology guard.
    std::function<void()> beforeNoOpTopologyGuard;
};

struct ScopedDefaultsLifecycleDeps {
    SudoersConfiguration* configuration = nullptr;
    ScopedDefaultsJournalAccess journal;
    SudoScopedDefaultsHooks hooks;
};

struct ScopedDefaultsLifecycleOutcome {
    bool ok = false;
    // No active scoped Defaults and no ownership change was needed.
    bool unchanged = false;
    // Ownership FIC still proves after this call.
    std::vector<SudoScopedDefaultsWrapperProof> owned;
    std::string message;
    std::vector<std::string> diagnostics;
};

// Outcome of resolving an unresolved Prepared record found at startup.
enum class PreparedRecoveryResult {
    NotPresent,
    CommittedExisting,    // filesystem == target (durable): existing -> Applied
    DiscardedExisting,    // FRESH: filesystem == previous, previous empty
    NormalizedExisting,   // REFRESH: filesystem == previous -> Applied(previous)
    CompensatedExisting,  // partial target selectively rewound to previous
    FailClosed
};

struct ScopedDefaultsRecoveryOutcome {
    PreparedRecoveryResult result = PreparedRecoveryResult::NotPresent;
    std::string message;
    std::vector<std::string> diagnostics;
};

class ScopedDefaultsLifecycle {
public:
    explicit ScopedDefaultsLifecycle(ScopedDefaultsLifecycleDeps deps);

    // Resolves an unresolved Prepared record for this policy. MUST run before
    // any ordinary reconciliation and MUST NOT mint new wrapper ids.
    ScopedDefaultsRecoveryOutcome recoverPrepared(const std::string& policyName);

    // Full production reconcile: recovery, ownership validation, planning,
    // prepare -> apply -> commit/discard.
    ScopedDefaultsLifecycleOutcome reconcile(const std::string& policyName);

    // THE ONLY helper allowed to discard a fresh SUDO Prepared record.
    //
    // capture (graph U target paths) -> FullyReleased(target) -> durability of
    // EXACTLY that capture -> discard. Used by every fresh-transition path:
    // CompletePrevious recovery, a failed mutation and a compensation back to
    // the empty previous side.
    // Re-proves that no @includedir the loaded graph was built from changed its
    // membership. `stage` names the decision being protected, for the message.
    // This is NOT a file capture: it closes the window where a brand-new
    // @includedir member appears that no capture path knows about.
    bool verifyTopologyUnchanged(const char* stage, std::string& error) const;

    bool resolveFreshPreparedToNoOwnership(
        MutationId mutationId,
        const std::vector<SudoScopedDefaultsWrapperProof>& targetProofs,
        ScopedDefaultsLifecycleOutcome& outcome);

    // Previous-side resolution proof for a refresh, on ONE snapshot generation:
    //
    //   capture( current graph U previous proof paths U target proof paths )
    //     -> Exact(previous), without the semantic invariant
    //     -> proveCapturedStateDurable( EXACTLY that capture )
    //
    // A SURVIVING target-only wrapper automatically fails Exact(previous): for
    // that expected set it is an UNKNOWN wrapper, so duplicates, drift, a missing
    // or moved previous wrapper, and any leftover target-only wrapper all fail
    // closed.
    //
    // The TARGET paths must be part of the capture because a target-only wrapper
    // may have fallen out of the current include graph (topology change) and
    // would otherwise stay invisible.
    //
    // FullyReleased is deliberately NOT used here: it is the whole-policy
    // TERMINAL contract (no FIC wrapper of this policy may survive) used by fresh
    // Prepared discard and rollback Success/NothingToDo. Applying it to the
    // target-only subset would wrongly demand the absence of the previous wrapper
    // that must survive a refresh rewind.
    bool provePreviousResolution(
        const std::string& policyName,
        const std::vector<SudoScopedDefaultsWrapperProof>& previousProofs,
        const std::vector<SudoScopedDefaultsWrapperProof>& targetProofs,
        ScopedDefaultsCapturedState& captured,
        std::string& error);

    // STRICT snapshot-bound resolution proof: capture -> exact ownership +
    // semantics on the SAME captures -> durability of EXACTLY those captures.
    // A journal transition may only follow this sequence.
    bool proveStrictState(
        const std::string& policyName,
        const std::vector<SudoScopedDefaultsWrapperProof>& proofs,
        ScopedDefaultsCapturedState& captured,
        std::string& error,
        bool requireNoActiveScopedDefaults = true);

    // Shared resolution of a Prepared record after a failed mutation. Used by
    // every error path so a failed REFRESH always normalizes back to the proven
    // previous ownership instead of deleting it.
    bool resolveAfterFailedMutation(
        MutationId mutationId,
        const std::vector<SudoScopedDefaultsWrapperProof>& previous,
        const std::vector<SudoScopedDefaultsWrapperProof>& target,
        SudoScopedDefaultsFilesystemState state,
        ScopedDefaultsLifecycleOutcome& outcome);

    // Active ownership proven by the journal for the canonical resource.
    // Fails closed when more than one active record exists, because several
    // active records would let corruption silently concatenate proof sets.
    static bool collectActiveOwnership(
        const std::vector<MutationRecord>& records,
        const std::string& resource,
        std::vector<SudoScopedDefaultsWrapperProof>& owned,
        std::string& error);

private:
    ScopedDefaultsLifecycleDeps deps_;
};

} // namespace fic::sudoers

#endif // FIC_SUDOERSSCOPEDDEFAULTSLIFECYCLE_H