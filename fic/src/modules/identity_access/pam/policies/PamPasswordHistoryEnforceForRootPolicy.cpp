#include "modules/identity_access/pam/policies/PamPasswordHistoryEnforceForRootPolicy.h"

#include <utility>

PamPasswordHistoryEnforceForRootPolicy::
    PamPasswordHistoryEnforceForRootPolicy(
        const fic::platform::PamPlatformConfig& platformConfig,
        PasswordCoordinatorFactory passwordCoordinatorFactory)
    : PamPasswordHistoryOptionPolicy(
          platformConfig,
          fic::platform::PamPolicyFeature::PasswordHistoryEnforceForRoot,
          std::move(passwordCoordinatorFactory)) {
    this->policyName = "password_history_enforce_for_root";
    this->policyTypeValue = std::make_unique<PossibleListPolicyTypeValue>(
        std::vector<std::string>{"yes", "no"});
}
