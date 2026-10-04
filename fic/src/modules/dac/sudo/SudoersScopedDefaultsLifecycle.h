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