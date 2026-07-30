#include "modules/auth/submodules/passwordquality/AUTH_password_min_length.h"

AUTH_password_min_length::AUTH_password_min_length(
    const fic::platform::PamPlatformConfig& platformConfig)
    : PamOptionPolicy(
          platformConfig,
          fic::auth::PamCapability::PasswordQuality,
          fic::auth::PamProviderKind::PamPwquality,
          platformConfig.passwordQualityConfigPath,
          "minlen",
          platformConfig.passwordServices) {
    this->submoduleName = "PasswordQuality";
    this->policyName = "password_min_length";
    this->policyTypeValue =
        std::make_unique<IntPolicyTypeValue>(6, 128, 12);
}
