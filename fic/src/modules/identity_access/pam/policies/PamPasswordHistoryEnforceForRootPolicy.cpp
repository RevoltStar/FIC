#include "modules/identity_access/pam/policies/PamPasswordHistoryEnforceForRootPolicy.h"

PamPasswordHistoryEnforceForRootPolicy::
    PamPasswordHistoryEnforceForRootPolicy(
        const fic::platform::PamPlatformConfig& platformConfig)
    : PamOptionPolicy(
          platformConfig,
          fic::identity::pam::PamCapability::PasswordHistory,
          fic::identity::pam::PamProviderKind::PamPwhistory,
          platformConfig.passwordHistoryConfigPath,
          "enforce_for_root",
          platformConfig.passwordServices,
          PamOptionSyntax::Flag) {
    this->policyName = "password_history_enforce_for_root";
    this->policyTypeValue = std::make_unique<PossibleListPolicyTypeValue>(
        std::vector<std::string>{"yes", "no"});
}
