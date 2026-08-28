#include "modules/identity_access/pam/policies/PamFailedAuthenticationEnforceForRootPolicy.h"

PamFailedAuthenticationEnforceForRootPolicy::
    PamFailedAuthenticationEnforceForRootPolicy(
        const fic::platform::PamPlatformConfig& platformConfig)
    : PamOptionPolicy(
          platformConfig,
          fic::platform::PamPolicyFeature::
              FailedAuthenticationEnforceForRoot) {
    this->policyName = "failed_authentication_enforce_for_root";
    this->policyTypeValue = std::make_unique<PossibleListPolicyTypeValue>(
        std::vector<std::string>{"yes", "no"});
}
