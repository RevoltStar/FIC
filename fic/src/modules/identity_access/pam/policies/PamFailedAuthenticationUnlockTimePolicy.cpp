#include "modules/identity_access/pam/policies/PamFailedAuthenticationUnlockTimePolicy.h"

PamFailedAuthenticationUnlockTimePolicy::PamFailedAuthenticationUnlockTimePolicy(
    const fic::platform::PamPlatformConfig& platformConfig)
    : PamOptionPolicy(
          platformConfig,
          fic::identity::pam::PamCapability::AuthenticationLockout,
          fic::identity::pam::PamProviderKind::PamFaillock,
          platformConfig.faillockConfigPath,
          "unlock_time",
          platformConfig.authenticationServices) {
    this->policyName = "failed_authentication_unlock_time";
    this->policyTypeValue =
        std::make_unique<IntPolicyTypeValue>(0, 86400, 600);
}
