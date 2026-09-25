#ifndef FIC_IDENTITY_ACCESS_PAM_PASSWORD_TOPOLOGY_PLANNER_H
#define FIC_IDENTITY_ACCESS_PAM_PASSWORD_TOPOLOGY_PLANNER_H

#include "modules/identity_access/pam/PamPasswordTopologyModel.h"

#include <string>
#include <vector>

namespace fic::identity::pam {

// Pure C2 password topology planner. The planner consumes the current
// semantic topology (physical FIC selections + foreign producer
// discovery), the runtime capability requests and the FIC journal
// ownership, and produces the desired FIC selection state plus an ORDERED
// list of semantic transition actions. It performs NO filesystem, journal
// or pam-auth-update mutation; the actual execution (with proofs,
// journal records and compensation) belongs to the later C2 runtime
// transition executor.
//
// Planner rules (v7 evidence baseline):
//   - Q=false, H=false: desired FIC selection is empty; a foreign quality
//     producer is NEVER removed.
//   - Q=true, H=false: select the FIC quality profile ONLY when no
//     foreign producer exists; a foreign producer satisfies the quality
//     capability untouched.
//   - H=true with a producer in the desired state (foreign or FIC
//     quality): select the history CONSUMER profile (use_authtok).
//   - H=true without any producer: select the history-INITIAL producer
//     profile (its slot is a producer without use_authtok). "History
//     requires quality" is wrong; history requires a token producer, and
//     history-initial IS that producer when none exists.
//   - Q=true, H=true without a producer: FIC quality + history CONSUMER,
//     never history-initial.
//   - Ownership-aware disable: only FIC-OWNED selected identifiers may be
//     detached. A physically selected but unproven (unowned) FIC
//     identifier is never removed (the removal would be based on
//     capability satisfaction, not provenance). Foreign selections are
//     never touched.
//   - Transitions between history variants are explicit topology
//     switches, not boolean toggles: Quality+History -> History-only
//     requires consumer -> initial producer, and History-only ->
//     Quality+History requires initial producer -> quality producer +
//     history consumer.
enum class PamPasswordPlanActionKind {
    AttachFicQuality,
    AttachFicHistoryInitial,
    AttachFicHistoryConsumer,
    DetachFicQuality,
    DetachFicHistoryInitial,
    DetachFicHistoryConsumer,
};

struct PamPasswordPlanAction {
    PamPasswordPlanActionKind kind =
        PamPasswordPlanActionKind::AttachFicQuality;

    // The FIC-owned activation profile identifier this action targets.
    const char* profileId() const;
};

struct PamPasswordTopologyPlan {
    // Desired FIC selection state (may be identical to the current one;
    // the actions list is then empty).
    bool wantFicQuality = false;
    bool wantFicHistoryInitial = false;
    bool wantFicHistoryConsumer = false;
    // Ordered semantic transition actions (producers before consumers,
    // consumers detached before their producer disappears).
    std::vector<PamPasswordPlanAction> actions;
    // false = planning failed closed (ambiguous current state or an
    // unsatisfiable ownership/selection conflict). error carries the
    // diagnostic; the desired-state fields are meaningless then.
    bool success = false;
    // Physically selected FIC identifiers that the desired state keeps
    // but the journal cannot prove FIC ownership for. The executor must
    // fail closed or resolve these before running any mutation.
    std::vector<std::string> unownedSelectionsPreserved;
    std::string error;
};

PamPasswordTopologyPlan planPamPasswordTopology(
    const PamPasswordTopology& current,
    bool qualityRequested,
    bool historyRequested,
    const PamPasswordOwnership& ownership);

} // namespace fic::identity::pam

#endif // FIC_IDENTITY_ACCESS_PAM_PASSWORD_TOPOLOGY_PLANNER_H
