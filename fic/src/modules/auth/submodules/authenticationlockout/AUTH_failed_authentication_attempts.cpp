#include "modules/auth/submodules/authenticationlockout/AUTH_failed_authentication_attempts.h"

AUTH_failed_authentication_attempts::AUTH_failed_authentication_attempts(
    const fic::platform::PamPlatformConfig& platformConfig)
    : PamOptionPolicy(
          platformConfig,
          fic::auth::PamCapability::AuthenticationLockout,
          fic::auth::PamProviderKind::PamFaillock,
          platformConfig.faillockConfigPath,
          "deny",
          platformConfig.authenticationServices) {
    this->submoduleName = "AuthenticationLockout";
    this->policyName = "failed_authentication_attempts";
    this->policyTypeValue =
        std::make_unique<IntPolicyTypeValue>(1, 20, 5);
}
