#include "modules/identity_access/pam/policies/PamPasswordHistoryDepthPolicy.h"

PamPasswordHistoryDepthPolicy::PamPasswordHistoryDepthPolicy(
    const fic::platform::PamPlatformConfig& platformConfig,
    PasswordCoordinatorFactory passwordCoordinatorFactory)
    : PamPasswordHistoryOptionPolicy(
          platformConfig,
          fic::platform::PamPolicyFeature::PasswordHistoryDepth,
          std::move(passwordCoordinatorFactory)) {
    this->policyName = "password_history_depth";
    this->policyTypeValue = std::make_unique<IntPolicyTypeValue>(
        static_cast<int>(kPasswordHistoryDepthMin),
        static_cast<int>(kPasswordHistoryDepthMax),
        static_cast<int>(kPasswordHistoryDepthDefault));
}