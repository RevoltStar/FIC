#include "modules/identity_access/submodules/pam/policies/PamFailedAuthenticationAttemptsPolicy.h"

PamFailedAuthenticationAttemptsPolicy::PamFailedAuthenticationAttemptsPolicy(
    const fic::platform::PamPlatformConfig& platformConfig)
    : PamOptionPolicy(
          platformConfig,
          fic::identity::pam::PamCapability::AuthenticationLockout,
          fic::identity::pam::PamProviderKind::PamFaillock,
          platformConfig.faillockConfigPath,
          "deny",
          platformConfig.authenticationServices) {
    this->policyName = "failed_authentication_attempts";
    this->policyTypeValue =
        std::make_unique<IntPolicyTypeValue>(1, 20, 5);
}
