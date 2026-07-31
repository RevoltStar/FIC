#include "modules/identity_access/submodules/pam/policies/PamPasswordHistoryDepthPolicy.h"

PamPasswordHistoryDepthPolicy::PamPasswordHistoryDepthPolicy(
    const fic::platform::PamPlatformConfig& platformConfig)
    : PamOptionPolicy(
          platformConfig,
          fic::identity::pam::PamCapability::PasswordHistory,
          fic::identity::pam::PamProviderKind::PamPwhistory,
          platformConfig.passwordHistoryConfigPath,
          "remember",
          platformConfig.passwordServices) {
    this->policyName = "password_history_depth";
    this->policyTypeValue =
        std::make_unique<IntPolicyTypeValue>(1, 50, 5);
}
