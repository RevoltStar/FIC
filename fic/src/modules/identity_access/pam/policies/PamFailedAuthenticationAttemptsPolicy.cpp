#include "modules/identity_access/pam/policies/PamFailedAuthenticationAttemptsPolicy.h"

PamFailedAuthenticationAttemptsPolicy::PamFailedAuthenticationAttemptsPolicy(
    const fic::platform::PamPlatformConfig& platformConfig)
    : PamOptionPolicy(
          platformConfig,
          fic::platform::PamPolicyFeature::FailedAuthenticationAttempts) {
    this->policyName = "failed_authentication_attempts";
    this->policyTypeValue =
        std::make_unique<IntPolicyTypeValue>(1, 20, 5);
}
