#ifndef FIC_SUDOERSSCOPEDDEFAULTSTRANSACTION_H
#define FIC_SUDOERSSCOPEDDEFAULTSTRANSACTION_H

#include "modules/dac/sudo/SudoersConfiguration.h"
#include "modules/dac/sudo/SudoersDisabledWrapper.h"

#include <fic/core/fs/AtomicFileWriter.h>

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

// WHY an operation ended. This says nothing about what is on disk.
enum class SudoScopedDefaultsResultKind {
    Success,
    Conflict,
    Failed
};

// What FIC-owned state is provably present on disk. This is the ONLY thing
// that may decide the fate of a Prepared journal record.
enum class SudoScopedDefaultsFilesystemState {
    // FIC provably published NO filesystem change at all.
    Unchanged,
    // FIC published changes and restored every one of them; this is proven.
    Compensated,
    // FIC published the complete target state and it is intended to stay.
    TargetInstalled,
    // FIC published something and the current on-disk state can no longer be
    // proven (compensation failed, CAS conflict, durability unknown).
    PartialOrUnknown
};

// The single invariant that governs the journal: a Prepared record may be
// discarded ONLY when nothing FIC-owned can remain. The failure REASON never
// decides this, so a pre-write Conflict (which proves zero writes) still
// permits discard, while a Failed operation that already installed a wrapper
// never does.
inline bool allowsDiscardPrepared(SudoScopedDefaultsFilesystemState state) {
    return state == SudoScopedDefaultsFilesystemState::Unchanged ||
        state == SudoScopedDefaultsFilesystemState::Compensated;
}

// True when FIC-owned state may still be present on disk, i.e. the Prepared
// journal record MUST stay active.
inline bool leavesOwnedState(SudoScopedDefaultsFilesystemState state) {
    return state == SudoScopedDefaultsFilesystemState::PartialOrUnknown;
}

struct SudoScopedDefaultsTransactionResult {
    SudoersOperationResult operation;
    SudoScopedDefaultsResultKind kind = SudoScopedDefaultsResultKind::Failed;
    SudoScopedDefaultsFilesystemState filesystemState =
        SudoScopedDefaultsFilesystemState::Unchanged;

    bool ok() const { return kind == SudoScopedDefaultsResultKind::Success; }
};

// Durability barrier for an ALREADY OBSERVED state: re-proves the exact current
// state of every path and only then confirms the directory entry. A visible
// file is not a durable file, so no journal transition may be justified by
// merely observing a wrapper.
bool proveObservedStateDurable(
    const std::vector<SudoScopedDefaultsWrapperProof>& proofs,
    std::string& error);

// The deduplicated physical files a proof set authorizes, in deterministic
// order. Used to run the durability barrier over exactly the proven scope.
std::vector<std::filesystem::path> proofPaths(
    const std::vector<SudoScopedDefaultsWrapperProof>& proofs);

// One physical scoped Defaults occurrence to suppress. A sudoers file may be
// included several times, so the same logical entry appears many times in the
// semantic view; remediation acts on PHYSICAL lines and must not wrap the
// same range twice.
struct ScopedDefaultsTarget {
    std::filesystem::path path;
    size_t firstLine = 0;
    size_t lineCount = 1;
};

// A proof permanently bound to ONE concrete physical target.
//
// The association must never be reconstructed from a positional cursor: the
// planner emits pairs, and grouping/sorting moves whole pairs, so a proof can
// only ever describe the payload of its own entry.
struct PlannedScopedDefaultsMutation {
    ScopedDefaultsTarget target;
    SudoScopedDefaultsWrapperProof proof;
};

// The result of one planning pass: what FIC already owns, and the new
// (target, proof) pairs to create. Both are produced together so the ids in
// the journal and the ids written to disk can never diverge.
struct ScopedDefaultsPlan {
    std::vector<SudoScopedDefaultsWrapperProof> owned;
    std::vector<PlannedScopedDefaultsMutation> fresh;
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
    // Deterministic seam invoked immediately BEFORE the rollback capture phase,
    // i.e. after the graph snapshot was taken. Lets a test model a concurrent
    // filesystem change inside exactly that window.
    std::function<void()> beforeCapture;
};

// Which contract an ownership proof must satisfy.
enum class ScopedDefaultsProofMode {
    // EVERY expected proof must physically exist, at its exact canonical path,
    // with its exact payload digest. Used before every journal transition that
    // RESOLVES a record (commit, normalization).
    Exact,
    // A proven wrapper that already disappeared is an already released subset.
    // Used only for intermediate rollback reasoning.
    ReleaseSubset,
    // NONE of the expected wrappers physically exists anywhere in the captured
    // graph, and no unknown/duplicate/drifted owned wrapper survives. Required
    // before a fresh Prepared discard, and before rollback Success/NothingToDo.
    FullyReleased
};

// Explicit state of ONE requested path.
//
// A requested path NEVER disappears from the captured state: it is either
// Present with a proven exact content, Absent with a proven durable absence, or
// the whole capture FAILED. A symlink, a directory, a permission or I/O error
// is never reclassified as absence.
enum class CapturedPathKind { Present, Absent };

struct CapturedSudoersDocument {
    std::filesystem::path path;
    CapturedPathKind kind = CapturedPathKind::Present;
    // Present only when kind == Present.
    AtomicTargetState state;
};

// ONE snapshot generation: every requested path with an explicit state.
struct ScopedDefaultsCapturedState {
    std::vector<CapturedSudoersDocument> documents;
};

struct ScopedDefaultsStateProof {
    bool ok = false;
    std::string message;
    // Carried so the caller can prove durability of exactly the proven state.
    ScopedDefaultsCapturedState captured;
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

    // Read-only, SNAPSHOT-BOUND ownership preflight.
    //
    // The current include graph is NOT the ownership authority. An external
    // process can remove an @include while the journal still proves ownership of
    // a wrapper that physically remains at its canonical path, so the capture
    // scope is the current graph UNION every `activeProofs` canonical path.
    //
    // On that ONE snapshot it verifies: the GLOBAL wrapper grammar, the GLOBAL
    // uniqueness of wrapper ids across the combined set (so a duplicate in a
    // graph file and in a proof-only path is detected), and that every existing
    // wrapper of this policy is proven by `activeProofs` naming that EXACT file
    // with an EXACT payload digest. Drift, a relocated wrapper, an unknown id,
    // a duplicate inside one file, malformed markers and any capture failure
    // (symlink, directory, permission, I/O) fail closed and are never
    // reclassified as an absence.
    //
    // A proven wrapper that physically disappeared is an already released
    // subset and stays NOT an error: that pre-existing external-release
    // contract is deliberately preserved here.
    //
    // Durability is intentionally not required, because no journal transition
    // happens here.
    //
    // This MUST run before a no-op AND before any new mutation, so an
    // unprovable ownership blocks reconciliation too, not just no-op.
    std::string validateCurrentOwnership(
        const std::vector<SudoScopedDefaultsWrapperProof>& activeProofs) const;

    // Same snapshot-bound ownership checks as validateCurrentOwnership(),
    // additionally requiring that no active scoped Defaults remain.
    std::string noopPreflight(
        const std::vector<SudoScopedDefaultsWrapperProof>& activeProofs) const;

    // Plans the NEXT transition on top of `owned` (the currently proven
    // ownership). Each new proof is returned BOUND to its physical target.
    ScopedDefaultsPlan plan(
        const std::vector<SudoScopedDefaultsWrapperProof>& owned) const;

    // Wraps every planned target. `fresh` must be the `fresh` list of a single
    // plan() call: proof and target travel together, never by position.
    SudoScopedDefaultsTransactionResult apply(
        const std::vector<PlannedScopedDefaultsMutation>& fresh,
        const SudoScopedDefaultsHooks& hooks);

    // Unwraps exactly the wrappers proven by `proofs`. Drift, an unknown id
    // or a duplicate id is a Conflict with ZERO writes.
    SudoScopedDefaultsTransactionResult release(
        const std::vector<SudoScopedDefaultsWrapperProof>& proofs,
        const SudoScopedDefaultsHooks& hooks);

    // Captures the exact state of every file the proofs reference PLUS every
    // current graph document, into ONE snapshot generation. A proof path outside
    // the include graph is still captured: ownership lives in a physical file,
    // and the include topology may have changed externally.
    // Returns false when a requested path could not be classified as Present or
    // Absent (symlink, directory, permission, I/O). Callers MUST fail closed:
    // a path is never silently dropped.
    bool captureProofAndGraphState(
        const std::vector<SudoScopedDefaultsWrapperProof>& proofs,
        ScopedDefaultsCapturedState& out,
        std::string& error) const;

    // Proves ownership over a CAPTURED snapshot: wrapper grammar, global
    // uniqueness of ids, exact path binding, exact payload digest, and (in Exact
    // mode) that EVERY expected proof physically exists. Also verifies, on the
    // SAME captures, that no active scoped Defaults remains outside a wrapper.
    // The returned proof carries the captures so the caller can confirm
    // durability of exactly this state.
    // `requireNoActiveScopedDefaults` is the TARGET-side invariant and must be
    // false when proving a PREVIOUS side: an unresolved refresh legitimately
    // leaves the new violation active until the re-plan suppresses it.
    ScopedDefaultsStateProof proveCapturedState(
        const std::vector<SudoScopedDefaultsWrapperProof>& proofs,
        const ScopedDefaultsCapturedState& captured,
        ScopedDefaultsProofMode mode,
        bool requireNoActiveScopedDefaults = true) const;

    // State-bound durability barrier over the EXACT captures that were proven.
    // A filesystem that changed since the capture fails closed.
    static bool proveCapturedStateDurable(
        const ScopedDefaultsCapturedState& captured, std::string& error);

    // SNAPSHOT-BOUND classification of an unresolved Prepared transition.
    //
    // It deliberately does NOT read the current include graph as authority: a
    // wrapper proven for a physical path can survive a topology change and no
    // longer be reachable through @include/@includedir. The capture set is the
    // union of the current graph and EVERY previous/target proof path, and the
    // comparison uses the FULL proof identity (id + path + digest).
    PreparedRecovery classifyCaptured(
        const std::vector<SudoScopedDefaultsWrapperProof>& previousProofs,
        const std::vector<SudoScopedDefaultsWrapperProof>& targetProofs,
        const ScopedDefaultsCapturedState& captured,
        std::string& error) const;

    // Classifies an unresolved Prepared transition against the live graph.
    PreparedRecovery classifyPrepared(
        const std::vector<SudoScopedDefaultsWrapperProof>& previousProofs,
        const std::vector<SudoScopedDefaultsWrapperProof>& targetProofs,
        std::string& error) const;

    // Compensates a PARTIAL target: removes only the wrappers that belong to
    // target but not to previous, using their exact proof plus CAS, so the
    // filesystem returns to the previous side. Used by Prepared recovery.
    // Returns false when the result can no longer be proven.
    bool compensateToPrevious(
        const std::vector<SudoScopedDefaultsWrapperProof>& previousProofs,
        const std::vector<SudoScopedDefaultsWrapperProof>& targetProofs,
        const SudoScopedDefaultsHooks& hooks,
        SudoScopedDefaultsFilesystemState& state,
        std::string& error) const;

private:
    SudoersConfiguration& configuration_;
    std::string policyName_;
};

} // namespace fic::sudoers

#endif // FIC_SUDOERSSCOPEDDEFAULTSTRANSACTION_H