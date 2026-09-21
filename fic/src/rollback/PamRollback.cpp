#include "rollback/PamRollback.h"

#include "modules/identity_access/pam/PamPlatformComposition.h"

#include <set>

namespace fic::rollback {
namespace {

using fic::identity::pam::PamTopologyState;

bool managedFaillockSlotDomain(const UndoDisablePamCapability& undo) {
    if (undo.capability != "enable_authentication_lockout" ||
        undo.topology != PamTopologyKind::PamAuthUpdate) {
        return false;
    }
    static const std::set<std::string> expected{
        "fic-faillock-hook-preauth",
        "fic-faillock-hook-authfail",
        "fic-faillock-hook-authsucc",
        "fic-faillock-hook-account"};
    return std::set<std::string>(
               undo.activationIdentifiers.begin(),
               undo.activationIdentifiers.end()) == expected;
}

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

PamRollbackResult undoPamCapability(
    const PamRollbackOptions& options,
    MutationId mutationId,
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

    if (managedFaillockSlotDomain(undo)) {
        if (mutationId == 0 ||
            !manager->bindJournalMutationId(mutationId, error)) {
            return {PamRollbackState::Conflict,
                    "PAM managed-slot rollback has no matching journal id: " +
                        error};
        }

        fic::identity::pam::PamTopologyStatus classified;
        std::string classificationError;
        const bool classifiedOk =
            manager->inspect(classified, classificationError);
        if (classifiedOk &&
            (classified.state == PamTopologyState::Disabled ||
             (classified.state == PamTopologyState::Enabled &&
              !classified.manageable))) {
            if (!manager->confirmDurable(error))
                return {PamRollbackState::Failed,
                        "PAM release durability unconfirmed: " + error};
            return {PamRollbackState::AlreadyReleased,
                    "FIC PAM managed slots are neutral"};
        }
        if (classifiedOk && classified.ownershipMutationId.has_value() &&
            *classified.ownershipMutationId != mutationId) {
            return {PamRollbackState::Conflict,
                    "FIC PAM managed slots belong to another journal mutation"};
        }

        // A crash can leave a strict partial set of exact markers. inspect()
        // correctly classifies that as Broken, but disable() is allowed to
        // neutralize only exact markers carrying this record id. Malformed
        // markers or another id are still refused by the manager.
        if (!manager->disable(error)) {
            return {PamRollbackState::Conflict,
                    "FIC PAM managed-slot release refused: " + error};
        }
        if (!manager->confirmDurable(error))
            return {PamRollbackState::Failed,
                    "PAM release durability unconfirmed: " + error};
        return {PamRollbackState::Released,
                "FIC PAM managed slots released"};
    }

    // Legacy pam-auth-update ownership is still profile-selection based.
    // semantic equality of the generated PAM graph. A structurally ambiguous
    // graph (for example concurrent distro pwquality + fic-pwquality) must not
    // block release of the exact FIC identifiers, and rollback must never
    // restore a snapshot over administrator selections.
    if (kind == PamTopologyKind::PamAuthUpdate) {
        fic::identity::pam::PamTopologyStatus classified;
        std::string classificationError;
        if (!manager->inspect(classified, classificationError)) {
            return {PamRollbackState::Conflict,
                    "legacy pam-auth-update ownership is indeterminate: " +
                        classificationError};
        }
        if (classified.state == PamTopologyState::Disabled ||
            (classified.state == PamTopologyState::Enabled &&
             !classified.manageable)) {
            if (!manager->confirmDurable(error))
                return {PamRollbackState::Failed,
                        "PAM release durability unconfirmed: " + error};
            return {PamRollbackState::AlreadyReleased,
                    "FIC pam-auth-update selection absent"};
        }
        if (!manager->disable(error))
            return {PamRollbackState::Failed,
                    "FIC pam-auth-update release failed: " + error};
        if (!manager->confirmDurable(error))
            return {PamRollbackState::Failed,
                    "PAM release durability unconfirmed: " + error};
        return {PamRollbackState::Released,
                "FIC pam-auth-update selection released"};
    }

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
        return {PamRollbackState::Conflict, "PAM topology is foreign"};
    }
    if (!manager->disable(error))
        return {PamRollbackState::Failed, "PAM release failed: " + error};
    fic::identity::pam::PamTopologyStatus after;
    if (!manager->inspect(after, error) ||
        after.state != PamTopologyState::Disabled) {
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
