#ifndef FIC_ROLLBACK_PAM_ROLLBACK_H
#define FIC_ROLLBACK_PAM_ROLLBACK_H

#include "modules/identity_access/pam/PamTopologyManager.h"
#include "rollback/MutationRecord.h"

#include <functional>
#include <memory>

namespace fic::rollback {

struct PamRollbackOptions {
    fic::platform::PamPlatformConfig platform;
    std::function<std::unique_ptr<fic::identity::pam::PamTopologyManager>(
        const fic::platform::PamCapabilityConfig&,
        const std::vector<std::string>&, std::string&)> managerFactory;
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
