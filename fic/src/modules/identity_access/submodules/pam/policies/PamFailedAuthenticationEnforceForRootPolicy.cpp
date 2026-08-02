#include "modules/identity_access/submodules/pam/policies/PamFailedAuthenticationEnforceForRootPolicy.h"

PamFailedAuthenticationEnforceForRootPolicy::
    PamFailedAuthenticationEnforceForRootPolicy(
        const fic::platform::PamPlatformConfig& platformConfig)
    : PamOptionPolicy(
          platformConfig,
          fic::identity::pam::PamCapability::AuthenticationLockout,
          fic::identity::pam::PamProviderKind::PamFaillock,
          platformConfig.faillockConfigPath,
          "even_deny_root",
          platformConfig.authenticationServices,
          PamOptionSyntax::Flag,
          {"root_unlock_time"}) {
    this->policyName = "failed_authentication_enforce_for_root";
    this->policyTypeValue = std::make_unique<PossibleListPolicyTypeValue>(
        std::vector<std::string>{"yes", "no"});
}
