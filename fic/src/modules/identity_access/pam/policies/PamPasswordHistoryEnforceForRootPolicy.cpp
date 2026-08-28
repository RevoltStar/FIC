#include "modules/identity_access/pam/policies/PamPasswordHistoryEnforceForRootPolicy.h"

PamPasswordHistoryEnforceForRootPolicy::
    PamPasswordHistoryEnforceForRootPolicy(
        const fic::platform::PamPlatformConfig& platformConfig)
    : PamOptionPolicy(
          platformConfig,
          fic::platform::PamPolicyFeature::PasswordHistoryEnforceForRoot) {
    this->policyName = "password_history_enforce_for_root";
    this->policyTypeValue = std::make_unique<PossibleListPolicyTypeValue>(
        std::vector<std::string>{"yes", "no"});
}
