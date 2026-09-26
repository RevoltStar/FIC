#ifndef FIC_IDENTITY_ACCESS_PAM_PASSWORD_TOPOLOGY_TRANSITION_EXECUTOR_H
#define FIC_IDENTITY_ACCESS_PAM_PASSWORD_TOPOLOGY_TRANSITION_EXECUTOR_H

#include "modules/identity_access/pam/PamManagedPasswordSlotWriter.h"
#include "modules/identity_access/pam/PamPasswordTopologyPlanner.h"
#include "modules/identity_access/pam/PamPasswordTopologyState.h"
#include "platform/PlatformExecutableResolver.h"

#include <fic/core/process/ProcessExecutor.h>

#include <rollback/MutationJournal.h>

#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>
#include <vector>

namespace fic::identity::pam {

// C2 runtime transition executor (production implementation).
//
// The executor performs ONE semantic topology transition per call:
//
//   inspect current physical topology (typed snapshot)
//   -> validate current state (classification + C2 safety + semantics)
//   -> compute the PURE plan (planPamPasswordTopology — the planner is the
//      ONLY semantic decision source; the executor never invents a desired
//      topology)
//   -> if the plan has no actions: fresh proof of the desired semantic
//      topology (no mutation, no new ownership)
//   -> for each planner action IN PLANNER ORDER:
//          prepare the slot state required by the action
//          (attach: Active slot FIRST, then selection — the unsafe window
//          "selected profile + Neutral slot" can never exist on the
//          successful path;
//           detach: selection removal FIRST, then the Neutral slot)
//          perform exactly ONE native pam-auth-update mutation per
//          invocation (ONE profile per invocation, never a batch)
//          immediate fresh resulting-state proof
//   -> final full three-profile topology proof
//
// Failure semantics:
//   - any failure after the first mutation compensates toward the PROVEN
//     pre-transition state (semantic inverse of the successfully proven
//     mutations in reverse order, executed through pam-auth-update and the
//     slot writers — never by copying generated files);
//   - compensation is fail-fast: the first failed or unproven inverse
//     mutation STOPS the compensation ("C2 PAM topology NOT proven
//     restored") instead of mutating further on an unknown topology;
//   - foreign state (stock pwquality producer) is NEVER claimed, removed
//     or overwritten; foreign drift detected between actions aborts the
//     stale plan and compensates only FIC-owned changes;
//   - physically selected but unowned FIC identities are never detached
//     (ownership-aware disable, planner contract);
//   - a native pam-auth-update call is never trusted by its exit status
//     alone: the resulting physical state is always freshly inspected
//     (rc=0 with a malformed result is a failure; rc!=0 with an exactly
//     proven result is accepted);
//   - changedSystemState is monotonic/honest: any possibly installed
//     change is reported even when the operation as a whole failed.
//
// Journal lifecycle: every slot mutation carries its own
// Prepared -> Applied record (or Applied -> RolledBack on deactivation)
// with the identity-specific activation identifier payload, exactly as
// journaled by PamManagedPasswordSlotWriter. The executor commits no
// separate transition record and never snapshots common-password —
// pam-auth-update remains the owner of the generated stack.

struct PamPasswordTopologyExecutorOptions {
    // Native mutator seam (tests). When unset, the resolved pam-auth-update
    // executable runs through the default ProcessExecutor.
    std::function<ProcessResult(
        const std::string& executable,
        const std::vector<std::string>& arguments,
        const ProcessOptions&)> runner;
    // Managed pwhistory module arguments of the history slot activations
    // (physical slot fields; the semantic enforcement is proven at the
    // proof layer).
    ManagedPwhistorySlotOptions historyOptions;
};

struct PamPasswordTransitionResult {
    bool success = false;
    // Monotonic: true iff the physical state may differ from the entry
    // state of this call (including non-compensatable partial changes).
    bool changedSystemState = false;
    PamPasswordTopologyClass topologyBefore =
        PamPasswordTopologyClass::Ambiguous;
    PamPasswordTopologyClass topologyAfter =
        PamPasswordTopologyClass::Ambiguous;
    // Profile identifiers of the successfully proven planner actions.
    std::vector<std::string> executedActions;
    // True when a failure triggered compensation of the attempted changes.
    bool compensated = false;
    // True only when the compensation PROVED the pre-transition state
    // again; false (with compensated == true) means the topology is NOT
    // proven restored (fail-fast stop or final proof failure).
    bool compensatedStateProven = false;
    std::string error;
};

class PamPasswordTopologyTransitionExecutor {
public:
    // journal must outlive the executor. configDirectory/stateDirectory
    // follow the PamPasswordStateInspectionOptions defaults (empty =
    // /etc/pam.d and /var/lib/pam).
    PamPasswordTopologyTransitionExecutor(
        fic::rollback::MutationJournal& journal,
        const fic::platform::PlatformExecutableResolver& executables,
        PamPasswordTopologyExecutorOptions options = {},
        std::filesystem::path configDirectory = {},
        std::filesystem::path stateDirectory = {});

    // Test-only deterministic seam of the underlying slot writers (same
    // model as PamManagedPasswordSlotWriter). Production code must never
    // set the hooks. slotIndex: 0 = quality or history-normal, 1 =
    // history-initial.
    using SlotFaultHook = PamManagedPasswordSlotWriter::SlotFaultHook;
    void setQualitySlotFaultHooksForTests(
        SlotFaultHook beforeWrite, SlotFaultHook afterWrite);
    void setHistorySlotFaultHooksForTests(
        SlotFaultHook beforeWrite, SlotFaultHook afterWrite);

    // Test-only deterministic seam of the journal Prepared -> Applied
    // completion of the underlying slot writers (see
    // PamManagedPasswordSlotWriter). Production code must never set it.
    using JournalCompletionFaultHook =
        PamManagedPasswordSlotWriter::JournalCompletionFaultHook;
    void setQualityJournalCompletionFaultHookForTests(
        JournalCompletionFaultHook hook);
    void setHistoryJournalCompletionFaultHookForTests(
        JournalCompletionFaultHook hook);
    // Test-only passthrough: injects a failure into history-writer C2
    // slot compensation (F12b). Production never installs this hook.
    using C2CompensationFaultHook =
        PamManagedPasswordSlotWriter::C2CompensationFaultHook;
    void setHistoryC2CompensationFaultHookForTests(
        C2CompensationFaultHook hook);

    // Executes the transition from the current physical topology to the
    // semantic topology requested by (qualityRequested, historyRequested).
    bool transition(
        bool qualityRequested, bool historyRequested,
        PamPasswordTransitionResult& result, std::string& error);

private:
    struct ActionAttempt {
        PamPasswordPlanActionKind kind =
            PamPasswordPlanActionKind::AttachFicQuality;
        // Attach: the slot is canonical Active with this journal id
        // (proven). Detach: 0.
        std::uint64_t slotMutationId = 0;
        // Attach: the native selection was attempted. Detach: the
        // selection/include absence was proven (the inverse must
        // re-attach).
        bool nativeAttempted = false;
        bool selectionRemovedProven = false;
    };

    bool runPamAuthUpdateOne(
        const char* flag, const char* profileId, std::string& error);
    bool inspectFresh(
        PamPasswordTopologySnapshot& snapshot, std::string& error);
    bool requireUsableCurrentState(
        const PamPasswordTopologySnapshot& snapshot, std::string& error);
    bool driftGate(
        const PamPasswordTopologySnapshot& expected, std::string& error);
    bool executeAction(
        const PamPasswordPlanAction& action, ActionAttempt& attempt,
        std::string& error);
    bool compensateAttempt(
        const ActionAttempt& attempt, bool& compensatedChanged,
        std::string& error);
    static PamPasswordTopologyClass desiredTopologyClass(
        const PamPasswordTopologyPlan& plan, bool foreignProducer);

    fic::rollback::MutationJournal& journal_;
    const fic::platform::PlatformExecutableResolver& executables_;
    PamPasswordTopologyExecutorOptions options_;
    PamPasswordStateInspectionOptions inspectionOptions_;
    std::filesystem::path configDirectory_;
    std::filesystem::path stateDirectory_;
    // Domain writers: quality identity + both history identities.
    PamManagedPasswordSlotWriter qualityWriter_;
    PamManagedPasswordSlotWriter historyWriter_;
};

} // namespace fic::identity::pam

#endif // FIC_IDENTITY_ACCESS_PAM_PASSWORD_TOPOLOGY_TRANSITION_EXECUTOR_H
