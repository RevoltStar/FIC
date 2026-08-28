#include "modules/identity_access/pam/policies/PamPasswordQualityPolicies.h"

#include <utility>

namespace {

constexpr int passwordQualityMaximum = 128;

} // namespace

PamPasswordCheckUsernamePolicy::PamPasswordCheckUsernamePolicy(
    const fic::platform::PamPlatformConfig& platformConfig)
    : PamOptionPolicy(
          platformConfig,
          fic::platform::PamPolicyFeature::PasswordCheckUsername) {
    this->policyName = "password_check_username";
    this->policyTypeValue = std::make_unique<PossibleListPolicyTypeValue>(
        std::vector<std::string>{"yes", "no"});
}

PamPasswordCheckGecosPolicy::PamPasswordCheckGecosPolicy(
    const fic::platform::PamPlatformConfig& platformConfig)
    : PamOptionPolicy(
          platformConfig,
          fic::platform::PamPolicyFeature::PasswordCheckGecos) {
    this->policyName = "password_check_gecos";
    this->policyTypeValue = std::make_unique<PossibleListPolicyTypeValue>(
        std::vector<std::string>{"yes", "no"});
}

PamPasswordQualityEnforceForRootPolicy::
    PamPasswordQualityEnforceForRootPolicy(
        const fic::platform::PamPlatformConfig& platformConfig)
    : PamOptionPolicy(
          platformConfig,
          fic::platform::PamPolicyFeature::PasswordQualityEnforceForRoot) {
    this->policyName = "password_quality_enforce_for_root";
    this->policyTypeValue = std::make_unique<PossibleListPolicyTypeValue>(
        std::vector<std::string>{"yes", "no"});
}

PamPasswordMinChangedCharactersPolicy::
    PamPasswordMinChangedCharactersPolicy(
        const fic::platform::PamPlatformConfig& platformConfig)
    : PamOptionPolicy(
          platformConfig,
          fic::platform::PamPolicyFeature::PasswordMinChangedCharacters) {
    this->policyName = "password_min_changed_characters";
    this->policyTypeValue =
        std::make_unique<IntPolicyTypeValue>(0, passwordQualityMaximum, 1);
}

PamPasswordMinimumCreditPolicy::PamPasswordMinimumCreditPolicy(
    const fic::platform::PamPlatformConfig& platformConfig,
    std::string policyName,
    fic::platform::PamPolicyFeature feature)
    : PamOptionPolicy(
          platformConfig,
          feature) {
    this->policyName = std::move(policyName);
    this->policyTypeValue =
        std::make_unique<IntPolicyTypeValue>(0, passwordQualityMaximum, 0);
}

PamPasswordMinLowercasePolicy::PamPasswordMinLowercasePolicy(
    const fic::platform::PamPlatformConfig& platformConfig)
    : PamPasswordMinimumCreditPolicy(
          platformConfig, "password_min_lowercase",
          fic::platform::PamPolicyFeature::PasswordMinLowercase) {
}

PamPasswordMinUppercasePolicy::PamPasswordMinUppercasePolicy(
    const fic::platform::PamPlatformConfig& platformConfig)
    : PamPasswordMinimumCreditPolicy(
          platformConfig, "password_min_uppercase",
          fic::platform::PamPolicyFeature::PasswordMinUppercase) {
}

PamPasswordMinDigitsPolicy::PamPasswordMinDigitsPolicy(
    const fic::platform::PamPlatformConfig& platformConfig)
    : PamPasswordMinimumCreditPolicy(
          platformConfig, "password_min_digits",
          fic::platform::PamPolicyFeature::PasswordMinDigits) {
}

PamPasswordMinOtherPolicy::PamPasswordMinOtherPolicy(
    const fic::platform::PamPlatformConfig& platformConfig)
    : PamPasswordMinimumCreditPolicy(
          platformConfig, "password_min_other",
          fic::platform::PamPolicyFeature::PasswordMinOther) {
}
