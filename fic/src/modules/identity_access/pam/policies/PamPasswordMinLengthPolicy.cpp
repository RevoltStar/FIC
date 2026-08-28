#include "modules/identity_access/pam/policies/PamPasswordMinLengthPolicy.h"

PamPasswordMinLengthPolicy::PamPasswordMinLengthPolicy(
    const fic::platform::PamPlatformConfig& platformConfig)
    : PamOptionPolicy(
          platformConfig,
          fic::platform::PamPolicyFeature::PasswordMinLength) {
    this->policyName = "password_min_length";
    this->policyTypeValue =
        std::make_unique<IntPolicyTypeValue>(6, 128, 12);
}
