#ifndef FIC_IDENTITY_ACCESS_PAM_PROVIDER_ROLLBACK_H
#define FIC_IDENTITY_ACCESS_PAM_PROVIDER_ROLLBACK_H

#include "modules/identity_access/pam/PamProviderCatalog.h"
#include "modules/identity_access/pam/PamProviderManagedBlock.h"
#include "platform/PlatformProfile.h"
#include "rollback/MutationRecord.h"
#include "rollback/MutationJournal.h"

#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace fic::identity::pam {

// ---------------------------------------------------------------------------
// Step 7F: dedicated production backend for the RUNTIME rollback of the
// managed provider configuration domain (assignments, set-only flags and
// the FIC-created container provenance).
//
// Immutable rollback principle: provider rollback RELEASES FIC OWNERSHIP —
// it never restores a historical administrator value. For an assignment the
// exact FIC-owned entry is removed and the foreign configuration naturally
// becomes effective; for a set-only flag the exact managed flag entry is
// removed and only the CURRENTLY EXISTING suppression wrappers whose
// provenance is authorized by the journal record are unwrapped. Foreign raw
// lines are never stored in the journal, never reconstructed and only ever
// returned from an existing physical wrapper; a missing wrapper is an
// externally released subset. There is NO whole-file snapshot rollback on
// this path: ownership release works exclusively through the exact
// ownership markers plus the journal provenance.
//
// PLACEMENT IS NOT OWNERSHIP (Step 7F): a valid FIC block that was displaced
// by foreign content is ineffective for compliance but the ownership still
// exists — rollback releases the exact entry/block anyway and preserves the
// foreign bytes byte-exact. The placement contract is used only to rebuild
// a surviving block, never to refuse the release.
//
// JOURNAL ORDER (per policy record): physical ownership release →
// durability proof → container resolution (if applicable) → Success/
// NothingToDo to the outer RollbackExecutor, which alone marks the policy
// record RolledBack. On Conflict/Failed the record stays active (or becomes
// RollbackFailed) and is never resolved before a durable physical release.
// A crash after the physical release but before the journal update is
// classified as "already released" on retry (idempotent; nothing is ever
// reconstructed).
//
// CONCURRENCY: the public undo functions serialize through the shared
// interprocess PamProviderManagedLock domain (the same lock the apply
// executors and the package release Stage B use). The *Unlocked primitives
// below are the lock-already-held variants used by the package release
// under its own outer lock — they must never be nested with the public API.
// ---------------------------------------------------------------------------
struct PamProviderRollbackResult {
    bool ok = false;
    bool nothingToDo = false;
    bool conflict = false;
    // True when this call (or a previous crashed attempt whose durability
    // could not be confirmed) already mutated the physical system state.
    bool changedSystemState = false;
    std::string message;
};

// Platform + test configuration of the backend.
struct PamProviderRollbackOptions {
    // CURRENT platform profile: every mutating rollback proves the journal
    // payload against THIS profile (provider kind/name, configuration mode,
    // config path, managed key, syntax, placement, pwhistory topology)
    // through the same typed routing helper the apply path uses. A journal
    // domain the current profile does not confirm is a Conflict — the
    // journaled path is never executed blindly.
    fic::platform::PamPlatformConfig platform;
    // Test-only deterministic fault seam. Production code must never set
    // it: simulates a journal resolution failure AFTER a durable container
    // delete / release (the retry must complete the lifecycle).
    std::function<bool()> simulateContainerJournalResolutionFailure;
};

// Typed routing proof of the CURRENT platform for one managed policy
// (single source of truth: the same pamProviderManagedEntryPlacement
// contract the apply path uses — no third whitelist).
struct PamProviderRollbackRoute {
    PamProviderDescriptor descriptor;
    const fic::platform::PamCapabilityConfig* capability = nullptr;
    PamProviderPolicyBinding binding;
    fic::platform::PamPolicyFeature feature =
        fic::platform::PamPolicyFeature::PasswordMinLength;
    PamProviderBlockPlacementRequest placement =
        PamProviderBlockPlacementRequest::End;
    std::filesystem::path configPath;
};

// Proves the managed rollback route for a FEATURE against the current
// platform. nullopt (with a typed message) when the platform does not
// route this feature through the managed provider configuration.
std::optional<PamProviderRollbackRoute> pamProviderRollbackRouteForFeature(
    const PamProviderRollbackOptions& options,
    fic::platform::PamPolicyFeature feature,
    std::string& conflictMessage);

// Payload-side platform identity proof (Step 7F §47/§48): the CURRENT
// platform must confirm the journaled provider identity, configuration
// path, managed key AND placement contract through the same typed routing
// helper the apply path uses. nullopt (with a typed message) = Conflict.
std::optional<PamProviderRollbackRoute> pamProviderRollbackRouteForPayload(
    const PamProviderRollbackOptions& options,
    const std::string& providerName,
    const std::string& configPath,
    const std::string& managedKey,
    fic::rollback::PamProviderBlockPlacementContract placementContract,
    std::string& conflictMessage);

// Typed managed-policy-name table (Step 7B-7E policy identities). Returns
// nullptr for any other policy name: an unknown future PAM policy never
// receives a default-positive enrollment.
const fic::platform::PamPolicyFeature* pamProviderManagedPolicyFeature(
    const std::string& policyName);

// Inverse SSOT lookup: the canonical FIC policy identity name of a managed
// PAM provider feature (same table as pamProviderManagedPolicyFeature), or
// nullptr when the feature is not routed through the managed provider
// configuration. Used by harnesses/drivers that must address journal and
// physical provenance with the SAME policy identity production uses.
const char* pamProviderManagedFeaturePolicyName(
    fic::platform::PamPolicyFeature feature);

// Single source of truth for the managed provider PRIMARY domain (Step 7F
// follow-up): "this capability is a real managed ProviderConfigFile domain,
// and this is its primary path". Eligibility comes from the configuration
// MODE plus a non-empty config path — NEVER from
// capability.configTopology.has_value(): production platform profiles carry
// the provider topology in provider.defaultConfigTopology, so a nullopt
// capability-level configTopology is the NORMAL routed shape (explicit
// capability.configTopology is only an override, see
// validatePamProviderConfigTopology). This is the same eligibility the
// typed routing proof (routeForPayload) applies.
std::optional<std::filesystem::path> pamProviderManagedPrimaryPath(
    const fic::platform::PamCapabilityConfig& capability);

// Deduplicated primary paths of every managed ProviderConfigFile capability
// of the platform: the only domain where FIC managed block/wrapper
// serialization can ever live. Package preflight/final-proof scan every
// path returned here.
std::vector<std::filesystem::path> pamProviderManagedPrimaryPaths(
    const fic::platform::PamPlatformConfig& platform);

// Public locked API (RollbackExecutor dispatch).
PamProviderRollbackResult undoPamProviderManagedEntry(
    const PamProviderRollbackOptions& options,
    fic::rollback::MutationJournal& journal,
    const fic::rollback::MutationRecord& record,
    const fic::rollback::UndoRemovePamProviderManagedEntry& undo);

PamProviderRollbackResult undoPamProviderManagedFlag(
    const PamProviderRollbackOptions& options,
    fic::rollback::MutationJournal& journal,
    const fic::rollback::MutationRecord& record,
    const fic::rollback::UndoRemovePamProviderManagedFlag& undo);

// UndoOwnPamProviderContainer for the package-release final sweep: releases
// a FIC-created container that provably holds no FIC state anymore
// (conditional delete of the exact current snapshot) or detaches the
// provenance when foreign content remains. A pre-existing file is never
// unlinked. NOT a user-policy rollback action.
PamProviderRollbackResult undoOwnPamProviderContainer(
    const PamProviderRollbackOptions& options,
    fic::rollback::MutationJournal& journal,
    const fic::rollback::MutationRecord& record,
    const fic::rollback::UndoOwnPamProviderContainer& undo);

// No-journal guard (Step 7F §58): for a managed provider policy WITHOUT an
// active journal record, proves that no orphan physical FIC state of this
// policy identity (managed entry or suppression wrapper marker) exists in
// the routed provider primary. Orphan markers are never adopted or removed
// — the caller reports a Conflict; no record AND no physical state means
// the disable may proceed.
PamProviderRollbackResult inspectUnrecordedPamProviderManagedState(
    const PamProviderRollbackOptions& options,
    const std::string& policyName);

// Internal lock-already-held primitives (package release Stage B). The
// caller MUST hold the shared PamProviderManagedLock domain.
PamProviderRollbackResult undoPamProviderManagedEntryUnlocked(
    const PamProviderRollbackOptions& options,
    fic::rollback::MutationJournal& journal,
    const fic::rollback::MutationRecord& record,
    const fic::rollback::UndoRemovePamProviderManagedEntry& undo);
PamProviderRollbackResult undoPamProviderManagedFlagUnlocked(
    const PamProviderRollbackOptions& options,
    fic::rollback::MutationJournal& journal,
    const fic::rollback::MutationRecord& record,
    const fic::rollback::UndoRemovePamProviderManagedFlag& undo);
PamProviderRollbackResult undoOwnPamProviderContainerUnlocked(
    const PamProviderRollbackOptions& options,
    fic::rollback::MutationJournal& journal,
    const fic::rollback::MutationRecord& record,
    const fic::rollback::UndoOwnPamProviderContainer& undo);

} // namespace fic::identity::pam

#endif // FIC_IDENTITY_ACCESS_PAM_PROVIDER_ROLLBACK_H
