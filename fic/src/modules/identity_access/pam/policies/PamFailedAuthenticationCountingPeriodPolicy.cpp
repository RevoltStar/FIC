#include "modules/identity_access/pam/policies/PamFailedAuthenticationCountingPeriodPolicy.h"

PamFailedAuthenticationCountingPeriodPolicy::
    PamFailedAuthenticationCountingPeriodPolicy(
        const fic::platform::PamPlatformConfig& platformConfig)
    : PamOptionPolicy(
          platformConfig,
          fic::platform::PamPolicyFeature::
              FailedAuthenticationCountingPeriod) {
    this->policyName = "failed_authentication_counting_period";
    this->policyTypeValue =
        std::make_unique<IntPolicyTypeValue>(1, 86400, 900);
}
