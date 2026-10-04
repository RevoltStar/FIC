#ifndef FIC_SUDOERSSCOPEDDEFAULTSTRANSACTION_H
#define FIC_SUDOERSSCOPEDDEFAULTSTRANSACTION_H

#include "modules/dac/sudo/SudoersConfiguration.h"
#include "modules/dac/sudo/SudoersDisabledWrapper.h"

#include <filesystem>
#include <functional>
#include <string>
#include <vector>

// Ownership + transaction model for the SUDO scoped-Defaults blocker
// (sudo_disable_scoped_defaults).
//
// This component owns ALL remediation for contextual Defaults: physical target
// planning/de-duplication, the GLOBAL wrapper inventory, wrapper provenance
// verification (id AND payload digest), Prepared/Applied refresh planning, the
// state-bound filesystem transaction with compensation, the typed outcome and
// the rollback/release transaction.
//
// It deliberately does NOT own sudoers parsing or the include graph: that stays
// in SudoersConfiguration, read through graphDocuments()/graphEntries(). No
// alias/user/host/command semantics are evaluated anywhere.
namespace fic::sudoers {

// Canonical identity of the blocker, shared with the mutation journal so the
// persisted record and the physical markers can never drift apart.
constexpr const char* kScopedDefaultsPolicyName = "sudo_disable_scoped_defaults";
constexpr const char* kSudoModuleName = "DAC";
constexpr const char* kSudoSubmoduleName = "SudoEdit";
// Canonical resource identity of the journal record: the wrapper namespace is
// the ownership domain, independent of the files involved.
constexpr const char* kScopedDefaultsResource = "sudo/scoped_defaults/wrappers";

// Typed transaction outcome. The caller MUST NOT infer "may I discard journal
// provenance" from a boolean: only NoMutation and MutatedAndCompensated prove
// that no FIC-owned filesystem state remains.
enum class SudoScopedDefaultsOutcome {
    NoMutation,
    MutatedAndCompensated,
    MutatedAndStillPresent,
    Success,
    Conflict
};

// True when FIC-owned state may still be present on disk, i.e. the Prepared
// journal record MUST stay active.
inline bool outcomeLeavesOwnedState(SudoScopedDefaultsOutcome outcome) {
    return outcome == SudoScopedDefaultsOutcome::MutatedAndStillPresent;
}

// True when the caller may safely discard the Prepared record.
inline bool outcomeAllowsDiscard(SudoScopedDefaultsOutcome outcome) {
    return outcome == SudoScopedDefaultsOutcome::NoMutation ||
        outcome == SudoScopedDefaultsOutcome::MutatedAndCompensated;
}

// One physical scoped Defaults occurrence to suppress. A sudoers file may be
// included several times, so the same logical entry appears many times in the
// semantic view; remediation acts on PHYSICAL lines and must not wrap the
// same range twice.
struct ScopedDefaultsTarget {
    std::filesystem::path path;
    size_t firstLine = 0;
    size_t lineCount = 1;
};

// Deterministic classification of an unresolved Prepared transition against
// the current physical state. Ambiguity is never guessed.
enum class PreparedRecovery {
    // Filesystem exactly matches the TARGET side: the transition provably
    // completed and may be committed as Applied.
    CompleteTarget,
    // Filesystem exactly matches the PREVIOUS side: the mutation provably
    // never landed; the Prepared record may be resolved as not-applied.
    CompletePrevious,
    // Filesystem matches neither side (partial or unexpected state).
    Indeterminate
};

// Injected filesystem operations; production uses the atomic writer, tests
// inject deterministic failures.
struct SudoScopedDefaultsHooks {
    // Re-runs visudo over the whole configuration.
    std::function<bool(std::string& error)> validate;
    // Re-reads the graph after a mutation and re-checks the semantic
    // postcondition. Returns true when no active scoped Defaults remain.
    std::function<bool(std::string& error)> reloadAndVerify;
    // Deterministic seam invoked right before each file write.
    std::function<void(const std::filesystem::path& path)> beforeWrite;
    // Deterministic seam invoked right before each compensation write.
    std::function<void(const std::filesystem::path& path)> beforeRestore;
};

class ScopedDefaultsTransaction {
public:
    ScopedDefaultsTransaction(SudoersConfiguration& configuration,
                              std::string policyName);

    const std::string& policyName() const { return policyName_; }

    // Physical, de-duplicated remediation targets in deterministic order.
    std::vector<ScopedDefaultsTarget> targets() const;

    // Every wrapper in the whole graph, with its owning file. Fails closed on
    // a malformed marker structure or on a wrapper id reused across different
    // files (one journal entry must never authorize two wrappers).
    struct OwnedWrapper {
        SudoDisabledWrapper wrapper;
        std::filesystem::path path;
    };
    bool globalInventory(std::vector<OwnedWrapper>& inventory,
                         std::string& error) const;

    // Read-only no-op preflight: "no active scoped Defaults" is NOT success by
    // itself. Every FIC wrapper of this policy must be proven by the ACTIVE
    // journal ownership set and the wrapper grammar must be intact. An orphan
    // wrapper is never adopted by creating a record for it. Returns an empty
    // string when the no-op is legitimate, otherwise the refusal reason.
    std::string noopPreflight(
        const std::vector<SudoScopedDefaultsWrapperProof>& activeProofs) const;

    // Plans the NEXT transition on top of `owned` (the currently proven
    // ownership). The new target proofs keep every wrapper FIC already owns,
    // so a repeated reconciliation grows the ownership set instead of
    // replacing it and orphaning the previously created wrappers.
    std::vector<SudoScopedDefaultsWrapperProof> planRefresh(
        const std::vector<SudoScopedDefaultsWrapperProof>& owned) const;

    // Wraps every current target. `targetProofs` must be exactly planRefresh()
    // applied to the currently owned set.
    SudoersOperationResult apply(
        const std::vector<SudoScopedDefaultsWrapperProof>& targetProofs,
        SudoScopedDefaultsOutcome& outcome,
        const SudoScopedDefaultsHooks& hooks);

    // Unwraps exactly the wrappers proven by `proofs`. Drift, an unknown id
    // or a duplicate id is a Conflict with ZERO writes.
    SudoersOperationResult release(
        const std::vector<SudoScopedDefaultsWrapperProof>& proofs,
        SudoScopedDefaultsOutcome& outcome,
        const SudoScopedDefaultsHooks& hooks);

    // Classifies an unresolved Prepared transition against the live graph.
    PreparedRecovery classifyPrepared(
        const std::vector<SudoScopedDefaultsWrapperProof>& previousProofs,
        const std::vector<SudoScopedDefaultsWrapperProof>& targetProofs,
        std::string& error) const;

private:
    SudoersConfiguration& configuration_;
    std::string policyName_;
};

} // namespace fic::sudoers

#endif // FIC_SUDOERSSCOPEDDEFAULTSTRANSACTION_H