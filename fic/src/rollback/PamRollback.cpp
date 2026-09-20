#include "rollback/PamRollback.h"

#include "modules/identity_access/pam/PamPlatformComposition.h"

namespace fic::rollback {
namespace {

using fic::identity::pam::PamTopologyState;

bool resolve(const PamRollbackOptions& options, const std::string& name,
             const fic::platform::PamCapabilityConfig*& capability,
             const std::vector<std::string>*& services,
             std::string& error) {
    fic::platform::PamCapability kind;
    if (name == "enable_authentication_lockout") {
        kind = fic::platform::PamCapability::AuthenticationLockout;
    } else if (name == "enable_password_history") {
        kind = fic::platform::PamCapability::PasswordHistory;
    } else if (name == "enable_password_quality") {
        kind = fic::platform::PamCapability::PasswordQuality;
    } else {
        error = "unsupported PAM capability rollback: " + name;
        return false;
    }
    return fic::identity::pam::resolveCapability(
        options.platform, kind, capability, services, error);
}

} // namespace

PamRollbackResult undoPamCapability(const PamRollbackOptions& options,
                                     const UndoDisablePamCapability& undo) {
    if (!options.managerFactory)
        return {PamRollbackState::Failed, "PAM manager factory unavailable"};
    const fic::platform::PamCapabilityConfig* capability = nullptr;
    const std::vector<std::string>* services = nullptr;
    std::string error;
    if (!resolve(options, undo.capability, capability, services, error))
        return {PamRollbackState::Failed, error};
    const auto kind = capability->topology ==
            fic::platform::PamTopologyStrategyKind::PamAuthUpdate
        ? PamTopologyKind::PamAuthUpdate : PamTopologyKind::AltTcbManaged;
    if (capability->topology ==
            fic::platform::PamTopologyStrategyKind::StaticVerifyOnly ||
        kind != undo.topology ||
        fic::identity::pam::activationIdentifiers(*capability) !=
            undo.activationIdentifiers) {
        return {PamRollbackState::Conflict,
                "PAM journal ownership domain differs from current profile"};
    }
    auto manager = options.managerFactory(*capability, *services, error);
    if (!manager) return {PamRollbackState::Failed, error};
    if (capability->activationOwnershipRequiresJournal &&
        !undo.confirmedNativeOwnership) {
        // Prepared alone proves intent, not which writer selected a shared
        // distro profile. Never release an ambiguous post-crash selection.
        fic::identity::pam::PamTopologyStatus unresolved;
        if (!manager->inspect(unresolved, error))
            return {PamRollbackState::Conflict, error};
        if (unresolved.state != PamTopologyState::Disabled)
            return {PamRollbackState::Conflict,
                    "fresh Prepared shared PAM selection has no ownership proof"};
        if (!manager->confirmDurable(error))
            return {PamRollbackState::Failed, error};
        return {PamRollbackState::AlreadyReleased,
                "fresh Prepared shared PAM selection is absent"};
    }
    manager->setJournalProvenance(true);
    fic::identity::pam::PamTopologyStatus before;
    if (!manager->inspect(before, error))
        return {PamRollbackState::Conflict, "PAM topology drift: " + error};
    if (before.state == PamTopologyState::Disabled) {
        if (!manager->confirmDurable(error))
            return {PamRollbackState::Failed,
                    "PAM release durability unconfirmed: " + error};
        return {PamRollbackState::AlreadyReleased, "FIC PAM topology absent"};
    }
    if (before.state != PamTopologyState::Enabled)
        return {PamRollbackState::Conflict, "PAM topology is not proven"};
    if (!before.manageable) {
        if (kind == PamTopologyKind::PamAuthUpdate) {
            if (!manager->confirmDurable(error))
                return {PamRollbackState::Failed,
                        "PAM release durability unconfirmed: " + error};
            return {PamRollbackState::AlreadyReleased,
                    "FIC selection absent; foreign PAM topology untouched"};
        }
        return {PamRollbackState::Conflict, "PAM topology is foreign"};
    }
    if (!manager->disable(error))
        return {PamRollbackState::Failed, "PAM release failed: " + error};
    fic::identity::pam::PamTopologyStatus after;
    if (!manager->inspect(after, error) ||
        (after.state != PamTopologyState::Disabled &&
         !(kind == PamTopologyKind::PamAuthUpdate &&
           after.state == PamTopologyState::Enabled && !after.manageable))) {
        return {PamRollbackState::Failed,
                "PAM release postcondition failed: " + error};
    }
    if (!manager->confirmDurable(error))
        return {PamRollbackState::Failed,
                "PAM release durability unconfirmed: " + error};
    return {PamRollbackState::Released, "FIC PAM topology released"};
}

PamRollbackResult inspectUnrecordedPamCapability(
    const PamRollbackOptions& options, const std::string& policyName) {
    const fic::platform::PamCapabilityConfig* capability = nullptr;
    const std::vector<std::string>* services = nullptr;
    std::string error;
    if (!resolve(options, policyName, capability, services, error))
        return {PamRollbackState::Failed, error};
    if (capability->topology ==
        fic::platform::PamTopologyStrategyKind::StaticVerifyOnly)
        return {PamRollbackState::AlreadyReleased,
                "Static PAM topology is not FIC-owned"};
    if (!options.managerFactory)
        return {PamRollbackState::Failed, "PAM manager factory unavailable"};
    auto manager = options.managerFactory(*capability, *services, error);
    if (!manager) return {PamRollbackState::Failed, error};
    fic::identity::pam::PamTopologyStatus status;
    if (!manager->inspect(status, error))
        return {PamRollbackState::Conflict,
                "PAM topology cannot be classified: " + error};
    if (status.state == PamTopologyState::Enabled && status.manageable)
        return {PamRollbackState::Conflict,
                "FIC-owned PAM topology has no active journal provenance"};
    if (status.state == PamTopologyState::Disabled ||
        (status.state == PamTopologyState::Enabled && !status.manageable))
        return {PamRollbackState::AlreadyReleased,
                "No journal-backed FIC PAM topology to release"};
    return {PamRollbackState::Conflict, "PAM topology is indeterminate"};
}

} // namespace fic::rollback
