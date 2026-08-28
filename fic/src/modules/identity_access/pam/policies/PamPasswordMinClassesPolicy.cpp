#include "modules/identity_access/pam/policies/PamPasswordMinClassesPolicy.h"

PamPasswordMinClassesPolicy::PamPasswordMinClassesPolicy(
    const fic::platform::PamPlatformConfig& platformConfig)
    : PamOptionPolicy(
          platformConfig,
          fic::platform::PamPolicyFeature::PasswordMinClasses) {
    this->policyName = "password_min_classes";
    this->policyTypeValue =
        std::make_unique<IntPolicyTypeValue>(1, 4, 3);
}
