#include "modules/identity_access/pam/policies/PamFailedAuthenticationCountingPeriodPolicy.h"

PamFailedAuthenticationCountingPeriodPolicy::
    PamFailedAuthenticationCountingPeriodPolicy(
        const fic::platform::PamPlatformConfig& platformConfig)
    : PamOptionPolicy(
          platformConfig,
          fic::identity::pam::PamCapability::AuthenticationLockout,
          fic::identity::pam::PamProviderKind::PamFaillock,
          platformConfig.faillockConfigPath,
          "fail_interval",
          platformConfig.authenticationServices) {
    this->policyName = "failed_authentication_counting_period";
    this->policyTypeValue =
        std::make_unique<IntPolicyTypeValue>(1, 86400, 900);
}
