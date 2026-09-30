#ifndef FIC_IDENTITY_ACCESS_PAM_PROVIDER_MANAGED_FLAG_EXECUTOR_H
#define FIC_IDENTITY_ACCESS_PAM_PROVIDER_MANAGED_FLAG_EXECUTOR_H

#include "modules/identity_access/pam/PamProviderCatalog.h"
#include "modules/identity_access/pam/PamProviderManagedBlock.h"
#include "modules/identity_access/pam/PamProviderManagedBlockFile.h"
#include "modules/identity_access/pam/PamProviderManagedEntryExecutor.h"
#include "platform/PlatformProfile.h"
#include "rollback/MutationJournal.h"

#include <filesystem>
#include <functional>
#include <string>

namespace fic::identity::pam {

// ---------------------------------------------------------------------------
// Step 7E production facade for journal-backed FIC-owned managed set-only
// flag ownership (even_deny_root / enforce_for_root) in a SHARED PAM
// provider primary configuration.
//
// Semantics (upstream presence flags — the config value never expresses
// false):
//   * desired=true  → FIC-owned bare managed key inside the managed block
//     (foreign active occurrences stay untouched: true is effective
//     regardless of foreign lines);
//   * desired=false → FIC-owned disabled sentinel entry PLUS FIC
//     suppression wrappers around EVERY suppressible foreign active
//     occurrence of the managed key. The foreign line is never deleted and
//     never stored in the journal: its exact bytes live inside the wrapper
//     (`raw=` suffix); the journal records only the suppression PROVENANCE
//     ids (a permission set, not a backup manifest). Rollback/Step 7F
//     removes the FIC entry and unwraps only the currently existing proven
//     wrappers — the foreign state returns naturally.
//
// Crash-safety: the durable-target-first state machine of Step 7B
// (prepare → ONE atomic physical transition (entry + wrappers in a single
// file replacement) → fresh trusted re-read → exact physical proof →
// semantic(target) → Applied; recovery completes the DURABLE target first
// and only then reconciles the current desired value, SAME record id).
// Toggles reuse ONE active record per policy identity — the same mutation
// id for the whole lifecycle (state and suppression-set refreshes only).
//
// CONCURRENCY CONTRACT: the caller MUST hold the shared PAM configuration
// lock (already held by PamPolicy::apply), exactly like the assignment
// executor.
// ---------------------------------------------------------------------------
struct PamProviderManagedFlagRequest {
    // FIC policy identity: journal PolicyRef is
    // IDENTITY_ACCESS / PAM / <policyName>; it is also the physical entry
    // marker policy token.
    std::string policyName;
    // Provider kind + identity token (descriptor.name, e.g. "pam_faillock").
    fic::platform::PamProviderKind provider =
        fic::platform::PamProviderKind::PamFaillock;
    std::string providerName;
    // Managed set-only key (e.g. even_deny_root / enforce_for_root).
    std::string managedKey;
    // Desired flag state.
    bool expectedEnabled = false;
    // Shared provider primary configuration path.
    std::filesystem::path configPath;
    // Placement contract of the provider configuration (derived from
    // pamProviderManagedEntryPlacement()).
    PamProviderBlockPlacementRequest placement =
        PamProviderBlockPlacementRequest::End;
};

class PamProviderManagedFlagExecutor {
public:
    // Semantic postcondition, PARAMETERIZED by the flag state being proven
    // (the DURABLE JOURNAL target during recovery, the current desired
    // value otherwise — the two may legitimately differ; the callback must
    // verify exactly the state it receives).
    using SemanticPostcondition =
        std::function<bool(bool expectedEnabled, std::string& error)>;

    // Executes one full managed-flag logical transaction against the given
    // USABLE journal. Production Step 7E works ONLY with a pre-existing
    // primary: an absent container fails closed before any journal
    // mutation (no flag-triggered container creation; Step 7F owns the
    // container release work). On any failure the durable journal state
    // stays recoverable (Prepared provenance is never discarded) and no
    // whole-file snapshot restore is ever performed.
    static bool apply(const PamProviderManagedFlagRequest& request,
                      fic::rollback::MutationJournal& journal,
                      const SemanticPostcondition& semantic,
                      PamProviderManagedEntryOutcome& outcome,
                      std::string& error);
};

} // namespace fic::identity::pam

#endif // FIC_IDENTITY_ACCESS_PAM_PROVIDER_MANAGED_FLAG_EXECUTOR_H