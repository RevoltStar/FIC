#include "modules/auth/submodules/authenticationlockout/AUTH_failed_authentication_unlock_time.h"

AUTH_failed_authentication_unlock_time::AUTH_failed_authentication_unlock_time(
    const fic::platform::PamPlatformConfig& platformConfig)
    : PamOptionPolicy(
          platformConfig,
          fic::auth::PamCapability::AuthenticationLockout,
          fic::auth::PamProviderKind::PamFaillock,
          platformConfig.faillockConfigPath,
          "unlock_time",
          platformConfig.authenticationServices) {
    this->submoduleName = "AuthenticationLockout";
    this->policyName = "failed_authentication_unlock_time";
    this->policyTypeValue =
        std::make_unique<IntPolicyTypeValue>(0, 86400, 600);
}
