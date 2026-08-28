#include "modules/identity_access/pam/policies/PamFailedAuthenticationUnlockTimePolicy.h"

PamFailedAuthenticationUnlockTimePolicy::PamFailedAuthenticationUnlockTimePolicy(
    const fic::platform::PamPlatformConfig& platformConfig)
    : PamOptionPolicy(
          platformConfig,
          fic::platform::PamPolicyFeature::
              FailedAuthenticationUnlockTime) {
    this->policyName = "failed_authentication_unlock_time";
    this->policyTypeValue =
        std::make_unique<IntPolicyTypeValue>(0, 86400, 600);
}
