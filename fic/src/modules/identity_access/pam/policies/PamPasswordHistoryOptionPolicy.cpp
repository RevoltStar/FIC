#include "modules/identity_access/pam/policies/PamPasswordHistoryOptionPolicy.h"

#include "modules/identity_access/pam/PamPlatformComposition.h"

#include <utility>

PamPasswordHistoryOptionPolicy::PamPasswordHistoryOptionPolicy(
    fic::platform::PamPlatformConfig platformConfig,
    fic::platform::PamPolicyFeature feature,
    PasswordCoordinatorFactory passwordCoordinatorFactory)
    : PamOptionPolicy(std::move(platformConfig), feature),
      passwordCoordinatorFactory_(std::move(passwordCoordinatorFactory)) {}

bool PamPasswordHistoryOptionPolicy::c2ManagedHistoryDomain() const {
    // platformConfig_ is a member of PamOptionPolicy; re-derive via the
    // capability lookup used everywhere else in this module.
    const auto* capability = fic::identity::pam::capabilityConfig(
        platformConfig_, fic::platform::PamCapability::PasswordHistory);
    return capability != nullptr &&
        capability->topology ==
            fic::platform::PamTopologyStrategyKind::PamAuthUpdate &&
        capability->configurationMode ==
            fic::platform::PamCapabilityConfigurationMode::ModuleArguments;
}

bool PamPasswordHistoryOptionPolicy::applyPam(
    const std::string& expectedValue) {
    if (!c2ManagedHistoryDomain()) {
        // Provider-config-file and legacy platforms keep the classic
        // option path unchanged (Step 6 does not touch it).
        return PamOptionPolicy::applyPam(expectedValue);
    }

    // C2 module-arguments domain: the joint coordinator is the ONLY
    // writer of the managed history slot options. The joint transition is
    // idempotent: it reconciles the topology toward the persisted
    // configuration intent AND the active history slot options in place
    // (no pam-auth-update call for a pure option change, no topology
    // activation from an option change).
    if (!passwordCoordinatorFactory_) {
        this->log("PAM joint password topology coordinator factory is "
                  "unavailable for " + this->policyName,
                  logLevel::ERROR);
        return false;
    }
    std::unique_ptr<fic::identity::pam::PamPasswordTopologyCoordinator>
        coordinator = passwordCoordinatorFactory_();
    if (!coordinator) {
        this->log("Could not create the PAM joint password topology "
                  "coordinator for " + this->policyName +
                      ": the daemon mutation journal is unavailable "
                      "(fail closed)",
                  logLevel::ERROR);
        return false;
    }
    std::string error;
    if (!coordinator->applyJointRequestedState(error)) {
        this->log("PAM joint password topology transition failed for " +
                      this->policyName + ": " + error,
                  logLevel::ERROR);
        return false;
    }
    const fic::identity::pam::PamPasswordTransitionResult& result =
        coordinator->lastResult();
    this->log("PAM policy " + this->policyName +
                  " is proven against the joint password configuration "
                  "intent" +
                  (result.executedActions.empty()
                       ? std::string(" (already proven; no mutation)")
                       : " (" +
                             std::to_string(result.executedActions.size()) +
                             " planner action(s) executed)"),
              logLevel::INFO);
    return true;
}
