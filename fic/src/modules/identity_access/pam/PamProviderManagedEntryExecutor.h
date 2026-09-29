#ifndef FIC_IDENTITY_ACCESS_PAM_PROVIDER_MANAGED_ENTRY_EXECUTOR_H
#define FIC_IDENTITY_ACCESS_PAM_PROVIDER_MANAGED_ENTRY_EXECUTOR_H

#include "modules/identity_access/pam/PamProviderCatalog.h"
#include "modules/identity_access/pam/PamProviderManagedBlock.h"
#include "modules/identity_access/pam/PamProviderManagedBlockFile.h"
#include "platform/PlatformProfile.h"
#include "rollback/MutationJournal.h"

#include <filesystem>
#include <functional>
#include <optional>
#include <string>

namespace fic::identity::pam {

// ---------------------------------------------------------------------------
// Step 7B production facade for journal-backed FIC-owned managed provider
// entries in a SHARED PAM provider primary configuration
// (/etc/security/faillock.conf class).
//
// One reusable lifecycle executor for ALL scalar provider assignment
// policies; concrete policies only supply the request. The executor owns
// the complete crash-safe state machine:
//
//   journal inspect → container read/trust proof → physical ownership
//   proof → prepare/refresh journal (Prepared) → physical write
//   (snapshot-CAS / exclusive create) → fresh trusted re-read → strict
//   parse → exact entry ownership + placement proof → semantic
//   postcondition → journal Applied
//
// It reuses the Step 7A primitives (PamProviderManagedBlock strict parser,
// ownership classifier, PamProviderManagedBlockFile trusted read/write)
// and NEVER duplicates the binding classifier. No historical administrator
// values are stored anywhere: FIC owns only its marked block/entries, and
// the whole-file snapshot rollback of the legacy writer is FORBIDDEN on
// this path (foreign/admin bytes survive every mutation byte-exact).
//
// CONCURRENCY CONTRACT: the caller MUST hold the shared PAM configuration
// lock (IdentityAccessPolicy::configurationMutex — already held by
// PamPolicy::apply) across the whole logical transaction; the executor
// deliberately creates NO local mutex, because a local one cannot protect
// the shared provider file against other policies of the same provider.
// Cross-process locking remains a separate (Step 7F) decision.
// ---------------------------------------------------------------------------
struct PamProviderManagedEntryRequest {
    // FIC policy identity: journal PolicyRef is
    // IDENTITY_ACCESS / PAM / <policyName>; it is also the physical entry
    // marker policy token.
    std::string policyName;
    // Provider kind + identity token (descriptor.name, e.g. "pam_faillock").
    fic::platform::PamProviderKind provider =
        fic::platform::PamProviderKind::PamFaillock;
    std::string providerName;
    // Managed key and desired native value; the canonical entry body is
    // "<managedKey> = <nativeValue>".
    std::string managedKey;
    std::string nativeValue;
    // Shared provider primary configuration path.
    std::filesystem::path configPath;
    // Placement contract of the provider configuration. Production callers
    // derive it through pamProviderManagedEntryPlacement() (faillock and
    // pwquality scalar assignments are last-wins → End).
    PamProviderBlockPlacementRequest placement =
        PamProviderBlockPlacementRequest::End;
    // Typed decision for a PROVEN-ABSENT primary. Production callers must
    // derive it through pamProviderAbsentContainerDecision(); tests and
    // future proven-safe platform paths may pass CreateFicOwned.
    PamProviderAbsentContainerDecision absentDecision =
        PamProviderAbsentContainerDecision::FailClosed;
};

// Step 7B/7C/7D routing decision: managed provider block path is used ONLY
// for the supported contract — provider-config-file mode, native
// Assignment syntax, and the explicitly whitelisted scalar assignment
// features PER PROVIDER (Step 7B: the three faillock scalars; Step 7C: the
// nine pam_pwquality scalars; Step 7D: pam_pwhistory password_history_depth
// on the ProviderConfigFile + PamAuthUpdate platforms — Debian 12
// ModuleArguments and ALT AltTcbManaged pwhistory stay on their existing
// Step 6/legacy paths). Everything else (module-argument policies, flags —
// even_deny_root and enforce_for_root stay Step 7E — pam_passwdqc/ALT
// topology paths, tally/tally2/cracklib/pam_unix remember) stays on the
// existing legacy path.
bool usesPamProviderManagedEntry(
    const PamProviderDescriptor& provider,
    const fic::platform::PamCapabilityConfig& capability,
    const PamProviderPolicyBinding& binding,
    fic::platform::PamPolicyFeature feature);

// Typed placement contract of the managed provider block for a routed
// (provider, feature) pair. Callers must derive the placement here instead
// of hardcoding it at the apply site, and the helper is TOTAL: an
// unroutable (provider, capability, feature) combination has NO placement
// (nullopt) — there is deliberately NO silent End fallback, so a future
// whitelisting mistake can never acquire EOF placement by accident.
//   * PamFaillock + 3 Step 7B scalars                  → End
//     (faillock.conf has last-wins sequential semantics);
//   * PamPwquality + 9 Step 7C scalars                 → End
//     (PwqualityConfigEvaluator DropInsThenPrimary model: EOF primary
//     outranks every drop-in and every earlier primary assignment);
//   * PamPwhistory + PasswordHistoryDepth
//     + ProviderConfigFile + PamAuthUpdate             → Beginning
//     (upstream pam_modutil_search_key FIRST-MATCH semantics: the FIC BOF
//     entry outranks every later foreign remember assignment).
// Everything else → nullopt.
std::optional<PamProviderBlockPlacementRequest> pamProviderManagedEntryPlacement(
    const PamProviderDescriptor& provider,
    const fic::platform::PamCapabilityConfig& capability,
    fic::platform::PamPolicyFeature feature);

// Typed provider/platform decision for a proven-absent primary container.
// Creating an explicit primary CHANGES the native fallback topology: for
// PamExplicitConfigSemantics::ReplacesNativeTopology (pam_faillock,
// pwhistory) a missing /etc/security/*.conf activates vendor defaults that
// FIC cannot prove deterministically today, so creation is refused
// (fail closed). No current platform profile carries the proof contract
// required for CreateFicOwned; a future proven-safe platform decision
// would be expressed HERE, never by silently creating the file.
PamProviderAbsentContainerDecision pamProviderAbsentContainerDecision(
    const PamProviderDescriptor& provider);

enum class PamProviderManagedEntryOutcome {
    // The desired state is proven effective; a physical mutation happened
    // in this apply (fresh create, refresh, recovery continuation or block
    // relocation) or the state was adopted after a crash.
    Applied,
    // Full proof chain succeeded WITHOUT any physical mutation: journal
    // Applied exact, physical entry exact (same id), provider exact,
    // placement satisfied, semantic postcondition effective.
    AppliedNoOp
};

class PamProviderManagedEntryExecutor {
public:
    // Production callers wire the existing verification pipeline
    // (PamCapabilityVerifier + PamProviderSemanticVerifier over the
    // configured services) here; unit tests inject an equivalent checker.
    // The executor runs it BEFORE every Applied transition — entry
    // ownership proof alone never proves PAM effectiveness.
    //
    // The postcondition is PARAMETERIZED by the exact native value of the
    // state being proven. The executor passes:
    //   * the DURABLE JOURNAL TARGET value while completing an unresolved
    //     Prepared transaction (the current desired value MUST NOT leak
    //     into an unfinished transaction), and
    //   * the CURRENT desired value for fresh applies, refreshes and no-op
    //     proofs.
    // Recovery target and current desired value may legitimately differ;
    // the callback must verify exactly the value it receives.
    using SemanticPostcondition = std::function<bool(
        const std::string& expectedNativeValue, std::string& error)>;

    // Executes one full managed-entry logical transaction for the request
    // against the given USABLE journal (fail closed when no usable journal
    // record/provenance exists — see the recovery matrix in the .cpp).
    // On any failure the durable journal state is left recoverable
    // (Prepared provenance is never discarded) and error carries a typed
    // diagnostic; no whole-file snapshot restore is ever performed.
    static bool apply(const PamProviderManagedEntryRequest& request,
                      fic::rollback::MutationJournal& journal,
                      const SemanticPostcondition& semantic,
                      PamProviderManagedEntryOutcome& outcome,
                      std::string& error);
};

} // namespace fic::identity::pam

#endif // FIC_IDENTITY_ACCESS_PAM_PROVIDER_MANAGED_ENTRY_EXECUTOR_H
