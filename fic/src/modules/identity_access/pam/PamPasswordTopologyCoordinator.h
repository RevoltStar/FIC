#ifndef FIC_IDENTITY_ACCESS_PAM_PASSWORD_TOPOLOGY_COORDINATOR_H
#define FIC_IDENTITY_ACCESS_PAM_PASSWORD_TOPOLOGY_COORDINATOR_H

#include "modules/identity_access/pam/PamPasswordTopologyTransitionExecutor.h"

#include <platform/PlatformExecutableResolver.h>
#include <platform/PlatformProfile.h>

#include <rollback/MutationJournal.h>

#include <filesystem>
#include <functional>
#include <memory>
#include <string>

namespace fic::identity::pam {

// Joint requested state of the ONE password runtime topology domain.
// Password Quality and Password History are NEVER two independent PAM
// activation mutations: the physical state is a joint (Q, H) topology
// (None / Quality / HistoryInitial / Quality+History / ForeignQuality /
// ForeignQuality+History), so every mutation decision is made for the
// PAIR. The requested state is the CONFIGURATION INTENT (module config),
// never the physical PAM topology and never one policy's value alone.
struct PamPasswordRequestedState {
    bool qualityRequested = false;
    bool historyRequested = false;
    // Step 6: desired managed pwhistory module arguments of the history
    // slot identities, read from the SAME configuration snapshot as the
    // joint (Q, H) request (never from the physical slots and never from
    // one policy's apply argument alone). On module-arguments platforms
    // (Debian 12) this is remember=N + enforce_for_root from the
    // IDENTITY_ACCESS configuration intent; on provider-config-file
    // platforms (e.g. Ubuntu 24.04 via /etc/security/pwhistory.conf) the
    // slot bodies carry no optional arguments and this stays default
    // (empty). Attachments render the slot from these options; an active
    // owned slot is reconciled in place toward them by the executor.
    ManagedPwhistorySlotOptions historyOptions{};
};

// Production coordinator of the joint password topology domain.
//
// Responsibility (exactly this and nothing more):
//   read the effective joint requested state (configuration intent)
//   -> invoke ONE PamPasswordTopologyTransitionExecutor.transition(Q, H)
//
// The executor is the only component that inspects, plans, mutates and
// proves the physical topology. The coordinator adds no semantic decisions
// and never calls pam-auth-update itself. Policy classes reach the physical
// domain exclusively through this coordinator, so a Quality-only apply
// still honors the current History request and vice versa.
//
// Concurrency contract: callers must hold the shared identity
// configuration mutex (IdentityAccessPolicy::configurationMutex) across
// the whole semantic transition (inspect/plan/mutate/proof). The
// coordinator does not lock internally (Policy::apply already holds it;
// a recursive lock would deadlock).
class PamPasswordTopologyCoordinator {
public:
    struct Options {
        // Test overrides; empty = platform defaults (/etc/pam.d,
        // /var/lib/pam).
        std::filesystem::path configDirectory;
        std::filesystem::path stateDirectory;
        // Executor options passthrough (test seams; production never
        // installs the test hooks).
        PamPasswordTopologyExecutorOptions executorOptions;
        // Desired-state reader seam (tests). When unset, the production
        // reader derives the joint requested state from the
        // IDENTITY_ACCESS module configuration intent
        // (enable_password_quality / enable_password_history ENABLE
        // statuses). Configuration intent is the authoritative desired
        // state; physical topology inspection belongs to the executor.
        std::function<bool(PamPasswordRequestedState&, std::string&)> desiredStateReader;
        // Test override of the config directory used by the production
        // desired-state reader (ModuleConfigFileHandler layout).
        std::filesystem::path identityConfigDirectory;
    };

    // journal must outlive the coordinator.
    PamPasswordTopologyCoordinator(
        fic::rollback::MutationJournal& journal,
        const fic::platform::PlatformExecutableResolver& executables,
        Options options = {});

    // Reads the joint configuration intent and performs ONE semantic
    // transition toward it. Idempotent: a proven desired topology is a
    // no-op success (no native mutation, no new journal ownership).
    bool applyJointRequestedState(std::string& error);

    // Explicit joint target (rollback wiring and tests). Same single
    // semantic transition contract as applyJointRequestedState.
    bool transition(
        const PamPasswordRequestedState& requested, std::string& error);

    // Honest transition result of the LAST transition call (including
    // failures with changedSystemState / compensated diagnostics).
    const PamPasswordTransitionResult& lastResult() const {
        return lastResult_;
    }

    // Test-only deterministic seam: inject a journal completion failure
    // into the underlying executor's history slot writer (the same seam
    // the executor exposes; used by the coordinator-level regression of
    // the option-update completion retry).
    void setHistoryJournalCompletionFaultHookForTests(
        PamManagedPasswordSlotWriter::JournalCompletionFaultHook hook);

    // Production wiring: coordinator over the daemon mutation journal
    // (DaemonMutationJournal) and the platform executable resolver with
    // the production desired-state reader (joint Q/H intent + managed
    // history options from one configuration snapshot, per the platform
    // pwhistory capability mode). Returns nullptr with a diagnostic when
    // the daemon journal is unavailable (fail closed).
    static std::unique_ptr<PamPasswordTopologyCoordinator> makeProduction(
        const fic::platform::PlatformExecutableResolver& executables,
        const fic::platform::PlatformProfile& platform,
        std::string& error);

private:
    bool readDesiredState(
        PamPasswordRequestedState& requested, std::string& error) const;
    std::string classifyFailure(const std::string& executorError) const;

    fic::rollback::MutationJournal& journal_;
    const fic::platform::PlatformExecutableResolver& executables_;
    Options options_;
    PamPasswordTopologyTransitionExecutor executor_;
    PamPasswordTransitionResult lastResult_;
};

// Joint configuration intent of the IDENTITY_ACCESS module (production
// desired-state reader, also used by the rollback wiring). Absent policy
// statuses count as NOT requested.
bool readJointPasswordConfigIntent(
    PamPasswordRequestedState& requested, std::string& error,
    std::filesystem::path identityConfigDirectory = {});

// Step 6: full joint desired state from ONE configuration snapshot — the
// joint (Q, H) request PLUS the managed history module options. On
// module-arguments platforms (Debian 12) the options come from the
// IDENTITY_ACCESS policy values:
//   password_history_depth            1..50; absent value uses the policy
//                                     default (kPasswordHistoryDepthDefault)
//   password_history_enforce_for_root yes -> token present, no/absent -> token
//                                     absent (bare option grammar)
// Malformed or out-of-range configured values fail closed (the coordinator
// never applies a partially known intent). On provider-config-file
// platforms the slot bodies carry no optional arguments: historyOptions
// stays default and the options are governed by the provider config file
// path through the classic option-policy path.
bool readJointPasswordDesiredState(
    PamPasswordRequestedState& requested,
    const fic::platform::PamPlatformConfig& platform,
    std::string& error,
    std::filesystem::path identityConfigDirectory = {});

} // namespace fic::identity::pam

#endif // FIC_IDENTITY_ACCESS_PAM_PASSWORD_TOPOLOGY_COORDINATOR_H