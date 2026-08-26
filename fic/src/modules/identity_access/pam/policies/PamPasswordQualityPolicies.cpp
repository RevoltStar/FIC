#include "modules/identity_access/pam/policies/PamPasswordQualityPolicies.h"

#include <utility>

namespace {

constexpr int passwordQualityMaximum = 128;

} // namespace

PamPasswordCheckUsernamePolicy::PamPasswordCheckUsernamePolicy(
    const fic::platform::PamPlatformConfig& platformConfig)
    : PamOptionPolicy(
          platformConfig,
          fic::identity::pam::PamCapability::PasswordQuality,
          fic::identity::pam::PamProviderKind::PamPwquality,
          platformConfig.passwordQualityConfigPath,
          "usercheck",
          platformConfig.passwordServices,
          PamOptionSyntax::Assignment,
          {},
          fic::identity::pam::PamOptionValueEncoding::YesNoInteger) {
    this->policyName = "password_check_username";
    this->policyTypeValue = std::make_unique<PossibleListPolicyTypeValue>(
        std::vector<std::string>{"yes", "no"});
}

PamPasswordCheckGecosPolicy::PamPasswordCheckGecosPolicy(
    const fic::platform::PamPlatformConfig& platformConfig)
    : PamOptionPolicy(
          platformConfig,
          fic::identity::pam::PamCapability::PasswordQuality,
          fic::identity::pam::PamProviderKind::PamPwquality,
          platformConfig.passwordQualityConfigPath,
          "gecoscheck",
          platformConfig.passwordServices,
          PamOptionSyntax::Assignment,
          {},
          fic::identity::pam::PamOptionValueEncoding::YesNoInteger) {
    this->policyName = "password_check_gecos";
    this->policyTypeValue = std::make_unique<PossibleListPolicyTypeValue>(
        std::vector<std::string>{"yes", "no"});
}

PamPasswordQualityEnforceForRootPolicy::
    PamPasswordQualityEnforceForRootPolicy(
        const fic::platform::PamPlatformConfig& platformConfig)
    : PamOptionPolicy(
          platformConfig,
          fic::identity::pam::PamCapability::PasswordQuality,
          fic::identity::pam::PamProviderKind::PamPwquality,
          platformConfig.passwordQualityConfigPath,
          "enforce_for_root",
          platformConfig.passwordServices,
          PamOptionSyntax::Flag) {
    this->policyName = "password_quality_enforce_for_root";
    this->policyTypeValue = std::make_unique<PossibleListPolicyTypeValue>(
        std::vector<std::string>{"yes", "no"});
}

PamPasswordMinChangedCharactersPolicy::
    PamPasswordMinChangedCharactersPolicy(
        const fic::platform::PamPlatformConfig& platformConfig)
    : PamOptionPolicy(
          platformConfig,
          fic::identity::pam::PamCapability::PasswordQuality,
          fic::identity::pam::PamProviderKind::PamPwquality,
          platformConfig.passwordQualityConfigPath,
          "difok",
          platformConfig.passwordServices) {
    this->policyName = "password_min_changed_characters";
    this->policyTypeValue =
        std::make_unique<IntPolicyTypeValue>(0, passwordQualityMaximum, 1);
}

PamPasswordMinimumCreditPolicy::PamPasswordMinimumCreditPolicy(
    const fic::platform::PamPlatformConfig& platformConfig,
    std::string policyName,
    std::string option)
    : PamOptionPolicy(
          platformConfig,
          fic::identity::pam::PamCapability::PasswordQuality,
          fic::identity::pam::PamProviderKind::PamPwquality,
          platformConfig.passwordQualityConfigPath,
          std::move(option),
          platformConfig.passwordServices,
          PamOptionSyntax::Assignment,
          {},
          fic::identity::pam::PamOptionValueEncoding::MinimumCredit) {
    this->policyName = std::move(policyName);
    this->policyTypeValue =
        std::make_unique<IntPolicyTypeValue>(0, passwordQualityMaximum, 0);
}

PamPasswordMinLowercasePolicy::PamPasswordMinLowercasePolicy(
    const fic::platform::PamPlatformConfig& platformConfig)
    : PamPasswordMinimumCreditPolicy(
          platformConfig, "password_min_lowercase", "lcredit") {
}

PamPasswordMinUppercasePolicy::PamPasswordMinUppercasePolicy(
    const fic::platform::PamPlatformConfig& platformConfig)
    : PamPasswordMinimumCreditPolicy(
          platformConfig, "password_min_uppercase", "ucredit") {
}

PamPasswordMinDigitsPolicy::PamPasswordMinDigitsPolicy(
    const fic::platform::PamPlatformConfig& platformConfig)
    : PamPasswordMinimumCreditPolicy(
          platformConfig, "password_min_digits", "dcredit") {
}

PamPasswordMinOtherPolicy::PamPasswordMinOtherPolicy(
    const fic::platform::PamPlatformConfig& platformConfig)
    : PamPasswordMinimumCreditPolicy(
          platformConfig, "password_min_other", "ocredit") {
}
