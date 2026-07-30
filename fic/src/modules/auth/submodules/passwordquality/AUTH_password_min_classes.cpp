#include "modules/auth/submodules/passwordquality/AUTH_password_min_classes.h"

AUTH_password_min_classes::AUTH_password_min_classes(
    const fic::platform::PamPlatformConfig& platformConfig)
    : PamOptionPolicy(
          platformConfig,
          fic::auth::PamCapability::PasswordQuality,
          fic::auth::PamProviderKind::PamPwquality,
          platformConfig.passwordQualityConfigPath,
          "minclass",
          platformConfig.passwordServices) {
    this->submoduleName = "PasswordQuality";
    this->policyName = "password_min_classes";
    this->policyTypeValue =
        std::make_unique<IntPolicyTypeValue>(1, 4, 3);
}
