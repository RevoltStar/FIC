#include "modules/identity_access/pam/policies/PamPasswordMinLengthPolicy.h"

PamPasswordMinLengthPolicy::PamPasswordMinLengthPolicy(
    const fic::platform::PamPlatformConfig& platformConfig)
    : PamOptionPolicy(
          platformConfig,
          fic::identity::pam::PamCapability::PasswordQuality,
          fic::identity::pam::PamProviderKind::PamPwquality,
          platformConfig.passwordQualityConfigPath,
          "minlen",
          platformConfig.passwordServices) {
    this->policyName = "password_min_length";
    this->policyTypeValue =
        std::make_unique<IntPolicyTypeValue>(6, 128, 12);
}
