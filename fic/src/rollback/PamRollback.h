#ifndef FIC_ROLLBACK_PAM_ROLLBACK_H
#define FIC_ROLLBACK_PAM_ROLLBACK_H

#include "modules/identity_access/pam/PamTopologyManager.h"
#include "rollback/MutationRecord.h"

#include <functional>
#include <memory>
#include <string>

namespace fic::rollback {

struct PamRollbackOptions {
    fic::platform::PamPlatformConfig platform;
    std::function<std::unique_ptr<fic::identity::pam::PamTopologyManager>(
        const fic::platform::PamCapabilityConfig&,
        const std::vector<std::string>&, std::string&)> managerFactory;

    // Joint C2 password topology rollback wiring (quality + history form
    // ONE joint topology domain; never rolled back profile-identifier by
    // profile-identifier):
    //  - jointTransition performs ONE semantic C2 topology transition to
    //    the requested joint target through the planner/executor
    //    (fresh inspect -> plan -> mutate -> proof);
    //  - jointRequestedState supplies the joint configuration intent of
    //    the surviving password capability for the rollback target.
    // Both must be wired for C2 password domains; without them the C2
    // password rollback fails closed (Conflict), never falls back to the
    // legacy per-profile disable path.
    struct JointTransitionOutcome {
        bool success = false;
        // Monotonic/honest: true iff the physical state may differ from
        // the entry state of this call (including unproven partial
        // changes). Never collapsed into a clean failure.
        bool changedSystemState = false;
        std::string error;
    };
    std::function<JointTransitionOutcome(
        bool qualityRequested, bool historyRequested, std::string& error)>
        jointTransition;
    std::function<bool(
        bool& qualityRequested, bool& historyRequested, std::string& error)>
        jointRequestedState;
};

enum class PamRollbackState { Released, AlreadyReleased, Conflict, Failed };
struct PamRollbackResult {
    PamRollbackState state = PamRollbackState::Failed;
    std::string message;
};

PamRollbackResult undoPamCapability(
    const PamRollbackOptions& options,
    MutationId mutationId,
    const UndoDisablePamCapability& undo);
// Compatibility overload for legacy/ALT direct unit tests. Managed-slot
// rollback requires a non-zero record id and will fail closed through it.
inline PamRollbackResult undoPamCapability(
    const PamRollbackOptions& options,
    const UndoDisablePamCapability& undo) {
    return undoPamCapability(options, 0, undo);
}
PamRollbackResult inspectUnrecordedPamCapability(
    const PamRollbackOptions& options, const std::string& policyName);

} // namespace fic::rollback

#endif
