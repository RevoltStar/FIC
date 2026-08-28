#include "modules/identity_access/pam/policies/PamPasswordHistoryDepthPolicy.h"

PamPasswordHistoryDepthPolicy::PamPasswordHistoryDepthPolicy(
    const fic::platform::PamPlatformConfig& platformConfig)
    : PamOptionPolicy(
          platformConfig,
          fic::platform::PamPolicyFeature::PasswordHistoryDepth) {
    this->policyName = "password_history_depth";
    this->policyTypeValue =
        std::make_unique<IntPolicyTypeValue>(1, 50, 5);
}
