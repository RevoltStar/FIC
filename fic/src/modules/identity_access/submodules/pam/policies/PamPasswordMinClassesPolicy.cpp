#include "modules/identity_access/submodules/pam/policies/PamPasswordMinClassesPolicy.h"

PamPasswordMinClassesPolicy::PamPasswordMinClassesPolicy(
    const fic::platform::PamPlatformConfig& platformConfig)
    : PamOptionPolicy(
          platformConfig,
          fic::identity::pam::PamCapability::PasswordQuality,
          fic::identity::pam::PamProviderKind::PamPwquality,
          platformConfig.passwordQualityConfigPath,
          "minclass",
          platformConfig.passwordServices) {
    this->policyName = "password_min_classes";
    this->policyTypeValue =
        std::make_unique<IntPolicyTypeValue>(1, 4, 3);
}
