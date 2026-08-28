#include "modules/identity_access/pam/policies/PamPasswdqcPolicies.h"

#include "modules/identity_access/pam/PasswdqcConfigFile.h"

#include <fic/core/i18n/LocalizationManager.h>
#include <fic/policy/PolicyTypeValue.h>

#include <limits>

namespace {

class PasswdqcMinimumsPolicyTypeValue final : public PolicyTypeValue {
public:
    PasswdqcMinimumsPolicyTypeValue()
    {
        defaultValue = "disabled,24,11,8,7";
    }

    PolicyEditorSpec getEditorSpec() const override
    {
        PolicyEditorSpec spec;
        spec.editor = "textedit";
        spec.validator = "none";
        return spec;
    }

    bool validate(const std::string& value) override
    {
        fic::identity::pam::PasswdqcMinimums parsed;
        std::string error;
        return fic::identity::pam::PasswdqcMinimumsCodec::parse(
            value, parsed, error);
    }

    std::string postProcessingValue(const std::string& value) override
    {
        return value;
    }

    std::string reverse_postProcessingValue(
        const std::string& value) override
    {
        return value;
    }

    std::string getPolicyRestrictionInfo() override
    {
        return LocalizationManager::getLang(
            "[utils:policytypevalue][type:passwdqcminimums]");
    }
};

} // namespace

PamPasswdqcStrengthThresholdsPolicy::PamPasswdqcStrengthThresholdsPolicy(
    const fic::platform::PamPlatformConfig& platformConfig)
    : PamOptionPolicy(
          platformConfig,
          fic::platform::PamPolicyFeature::PasswdqcStrengthThresholds)
{
    policyName = "passwdqc_strength_thresholds";
    policyTypeValue = std::make_unique<PasswdqcMinimumsPolicyTypeValue>();
}

PamPasswdqcPassphraseWordsPolicy::PamPasswdqcPassphraseWordsPolicy(
    const fic::platform::PamPlatformConfig& platformConfig)
    : PamOptionPolicy(
          platformConfig,
          fic::platform::PamPolicyFeature::PasswdqcPassphraseWords)
{
    policyName = "passwdqc_passphrase_words";
    policyTypeValue = std::make_unique<IntPolicyTypeValue>(
        0, std::numeric_limits<int>::max(), 3);
}

PamPasswdqcMatchLengthPolicy::PamPasswdqcMatchLengthPolicy(
    const fic::platform::PamPlatformConfig& platformConfig)
    : PamOptionPolicy(
          platformConfig,
          fic::platform::PamPolicyFeature::PasswdqcMatchLength)
{
    policyName = "passwdqc_match_length";
    policyTypeValue = std::make_unique<IntPolicyTypeValue>(
        0, std::numeric_limits<int>::max(), 4);
}

PamPasswdqcSimilarPasswordPolicy::PamPasswdqcSimilarPasswordPolicy(
    const fic::platform::PamPlatformConfig& platformConfig)
    : PamOptionPolicy(
          platformConfig,
          fic::platform::PamPolicyFeature::PasswdqcSimilarPassword)
{
    policyName = "passwdqc_similar_password";
    policyTypeValue = std::make_unique<PossibleListPolicyTypeValue>(
        std::vector<std::string>{"deny", "permit"});
}

PamPasswdqcRetryCountPolicy::PamPasswdqcRetryCountPolicy(
    const fic::platform::PamPlatformConfig& platformConfig)
    : PamOptionPolicy(
          platformConfig,
          fic::platform::PamPolicyFeature::PasswdqcRetryCount)
{
    policyName = "passwdqc_retry_count";
    policyTypeValue = std::make_unique<IntPolicyTypeValue>(
        0, std::numeric_limits<int>::max(), 3);
}
