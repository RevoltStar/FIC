#include "modules/auth/submodules/passwordhistory/AUTH_password_history_depth.h"

AUTH_password_history_depth::AUTH_password_history_depth(
    const fic::platform::PamPlatformConfig& platformConfig)
    : PamOptionPolicy(
          platformConfig,
          fic::auth::PamCapability::PasswordHistory,
          fic::auth::PamProviderKind::PamPwhistory,
          platformConfig.passwordHistoryConfigPath,
          "remember",
          platformConfig.passwordServices) {
    this->submoduleName = "PasswordHistory";
    this->policyName = "password_history_depth";
    this->policyTypeValue =
        std::make_unique<IntPolicyTypeValue>(1, 50, 5);
}
