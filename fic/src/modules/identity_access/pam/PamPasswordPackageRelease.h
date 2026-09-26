#ifndef FIC_IDENTITY_ACCESS_PAM_PASSWORD_PACKAGE_RELEASE_H
#define FIC_IDENTITY_ACCESS_PAM_PASSWORD_PACKAGE_RELEASE_H

#include "modules/identity_access/pam/PamManagedPasswordSlotWriter.h"
#include "modules/identity_access/pam/PamPasswordTopologyState.h"
#include "modules/identity_access/pam/PamPasswordTopologyTransitionExecutor.h"

#include <platform/PlatformExecutableResolver.h>

#include <rollback/MutationJournal.h>

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace fic::identity::pam {

// Package-maintenance release of the C2 password topology domain.
//
// This is the single authority the Debian prerm uses before the package
// payload (profile definitions, managed slot conffiles) may be removed.
// It is NOT a policy rollback: the desired state is always the package
// lifecycle target (qualityRequested = false, historyRequested = false)
// and never derives from IDENTITY_ACCESS configuration intent.
//
// Contract:
//   preflight  — strictly read-only early check (Stage A). Proves the
//                current physical password topology is inspectable and
//                package-release eligible BEFORE any side effect (no
//                service stop, no pam-auth-update, no slot write, no
//                journal lifecycle write). Selected-but-unowned FIC
//                identities, ambiguous/unsafe topologies and incoherent
//                state fail closed here.
//   release    — the package-release transition (Stage B, after every FIC
//                writer has been stopped):
//                  fresh re-inspection (the Stage A snapshot is never
//                  trusted) -> exclusive cross-process mutation lock ->
//                  recovery of provable exact-id Prepared crash-leftovers
//                  (production compensation primitive only) -> ONE
//                  PamPasswordTopologyTransitionExecutor.transition(false,
//                  false) (planner-ordered, one profile per native
//                  mutation, per-action proofs, C2 compensation on
//                  failure) -> independent final proof.
//
// Ownership semantics: a physically selected FIC profile is detached ONLY
// when journal provenance proves FIC ownership (Applied record with the
// role-specific activation identifier). Foreign (stock pwquality) state
// is never claimed, removed or overwritten; a foreign producer present
// before the release must still be present after it. The final semantic
// topology is proven to be exactly None or ForeignQuality.
//
// Journal semantics: slot ownership records follow the existing writer
// lifecycle (Applied -> RolledBack on release; a recovered exact-id
// Prepared record is discarded). The journal file is never deleted and
// unrelated records are never touched. A stale Prepared record whose slot
// is already Neutral is inert for the package release target and is left
// for the existing activation recovery matrix (no parallel cleanup path).
//
// Failure semantics: any failure after the first mutation is compensated
// by the executor toward the proven pre-release topology. If compensation
// is proven, the caller may safely retry the package removal later; if
// compensation is NOT proven, the error carries an explicit CRITICAL
// classification and the package removal must stay blocked.
class PamPasswordPackageRelease {
public:
    enum class Mode {
        // Stage A: read-only early eligibility proof.
        Preflight,
        // Stage B: locked fresh re-inspection + recovery + transition +
        // final proof.
        Release
    };

    struct Options {
        // Empty = platform defaults (/etc/pam.d, /var/lib/pam) — the same
        // normalization contract as the transition executor.
        std::filesystem::path configDirectory;
        std::filesystem::path stateDirectory;
        // Cross-process mutation serialization of the release stage
        // (Stage B) against other local maintenance invocations. Empty
        // disables the lock (tests). The runtime daemon must be stopped
        // by the caller BEFORE the release stage (prerm stop ordering);
        // the lock never substitutes the service stop.
        std::filesystem::path lockFilePath;
        std::string lockDebugLogPath;
        // Executor options passthrough (test runner seam; production
        // never sets the hooks).
        PamPasswordTopologyExecutorOptions executorOptions;
    };

    struct Report {
        PamPasswordTopologyClass topologyBefore =
            PamPasswordTopologyClass::Ambiguous;
        PamPasswordTopologyClass topologyAfter =
            PamPasswordTopologyClass::Ambiguous;
        // Exact-id Prepared crash-leftovers recovered by this release
        // (profile identifiers, planner order).
        std::vector<std::string> recoveredCrashLeftovers;
        // FIC identities detached by the transition (profile identifiers,
        // planner order).
        std::vector<std::string> detachedIdentities;
        // Executor accounting (monotonic, honest).
        bool changedSystemState = false;
        bool compensated = false;
        bool compensatedStateProven = false;
        bool foreignProducerPresent = false;
    };

    // journal must outlive the release object.
    PamPasswordPackageRelease(
        fic::rollback::MutationJournal& journal,
        const fic::platform::PlatformExecutableResolver& executables,
        Options options);

    bool run(Mode mode, Report& report, std::string& error);

    // Test-only deterministic seams of the internal transition executor
    // (same model as PamPasswordTopologyTransitionExecutor). Production
    // code must never set the hooks.
    using SlotFaultHook = PamManagedPasswordSlotWriter::SlotFaultHook;
    using JournalCompletionFaultHook =
        PamManagedPasswordSlotWriter::JournalCompletionFaultHook;
    using C2CompensationFaultHook =
        PamManagedPasswordSlotWriter::C2CompensationFaultHook;
    void setQualitySlotFaultHooksForTests(
        SlotFaultHook beforeWrite, SlotFaultHook afterWrite);
    void setHistorySlotFaultHooksForTests(
        SlotFaultHook beforeWrite, SlotFaultHook afterWrite);
    void setQualityJournalCompletionFaultHookForTests(
        JournalCompletionFaultHook hook);
    void setHistoryJournalCompletionFaultHookForTests(
        JournalCompletionFaultHook hook);
    void setHistoryC2CompensationFaultHookForTests(
        C2CompensationFaultHook hook);

private:
    struct IdentityView {
        const char* profileId;
        bool selected;
        bool owned;
        bool prepared;
        ManagedPasswordSlotState slotState;
        std::uint64_t slotMutationId;
        ManagedPasswordSlotRole role;
    };

    // Fresh inspection + structural eligibility gate. Fails closed on
    // inspection errors, incoherent state, selected-but-unowned
    // identities, unselected-owned identities and both history variants.
    // Recoverable exact-id Prepared crash-leftovers are reported and
    // tolerated: in preflight their Active slots are virtually
    // neutralized before the safety/semantics gates; in release they MUST
    // be recovered before this gate runs again.
    bool inspectAndCheckStructure(
        PamPasswordTopologySnapshot& snapshot,
        std::vector<IdentityView>& leftovers, std::string& error);
    // Safety/semantics/classification gate over an in-memory virtually
    // recovered copy of the snapshot.
    bool checkSafetyAndSemantics(
        const PamPasswordTopologySnapshot& snapshot,
        const std::vector<IdentityView>& leftovers, std::string& error);
    // Release-stage recovery of exact-id Prepared crash-leftovers through
    // the production compensation primitive, followed by a fresh proof.
    bool recoverCrashLeftovers(
        const std::vector<IdentityView>& leftovers, Report& report,
        std::string& error);
    // Independent final resulting-state proof.
    bool proveFinalState(
        const PamPasswordTopologySnapshot& pre, Report& report,
        std::string& error);
    // Per-identity projection of a snapshot (planner order).
    auto identityViews(const PamPasswordTopologySnapshot& snapshot) const
        -> std::vector<IdentityView>;

    fic::rollback::MutationJournal& journal_;
    Options options_;
    PamPasswordTopologyTransitionExecutor executor_;
    // Domain writers mirror the executor's construction exactly (same
    // config directory normalization, same journal).
    PamManagedPasswordSlotWriter qualityWriter_;
    PamManagedPasswordSlotWriter historyWriter_;
};

} // namespace fic::identity::pam

#endif // FIC_IDENTITY_ACCESS_PAM_PASSWORD_PACKAGE_RELEASE_H