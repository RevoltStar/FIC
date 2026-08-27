#include "modules/identity_access/pam/policies/RequiredPamEnforcementPolicy.h"

#include "modules/identity_access/pam/PamCapabilityVerifier.h"
#include "modules/identity_access/pam/PamConfiguration.h"
#include "modules/identity_access/pam/PamRequiredProviders.h"
#include "platform/RequiredPamEnforcementDefaultsGenerated.h"

#include <iostream>
#include <sstream>
#include <utility>

namespace {

class RequiredPamPolicyTypeValue final : public PolicyTypeValue {
public:
    RequiredPamPolicyTypeValue() {
        this->defaultValue = FIC_REQUIRED_PAM_ENFORCEMENT_DEFAULT;
    }

    PolicyEditorSpec getEditorSpec() const override {
        PolicyEditorSpec spec;
        spec.editor = "textedit";
        spec.textDelimiter = ",";
        return spec;
    }

    bool validate(const std::string& value) override {
        std::vector<fic::identity::pam::PamProviderKind> providers;
        std::string normalized;
        std::string error;
        const bool valid = fic::identity::pam::parseRequiredPamProviders(
            value, providers, normalized, error);
        if (!valid) {
            std::cerr << "Invalid required PAM provider list: " << error << '\n';
        }
        return valid;
    }

    std::string postProcessingValue(const std::string& value) override {
        std::vector<fic::identity::pam::PamProviderKind> providers;
        std::string normalized;
        std::string error;
        return fic::identity::pam::parseRequiredPamProviders(
                   value, providers, normalized, error)
            ? normalized
            : "";
    }

    std::string reverse_postProcessingValue(
        const std::string& value) override {
        return value;
    }

    std::string getPolicyRestrictionInfo() override {
        std::ostringstream restriction;
        restriction << "Comma-separated supported PAM providers: ";
        const auto& names = fic::identity::pam::requiredPamProviderNames();
        for (std::size_t index = 0; index < names.size(); ++index) {
            if (index != 0) {
                restriction << ", ";
            }
            restriction << names[index];
        }
        return restriction.str();
    }
};

std::pair<fic::identity::pam::PamCapability, std::vector<std::string>>
capabilityAndServices(
    fic::identity::pam::PamProviderKind provider,
    const fic::platform::PamPlatformConfig& platform) {
    switch (provider) {
    case fic::identity::pam::PamProviderKind::PamFaillock:
        return {fic::identity::pam::PamCapability::AuthenticationLockout,
                platform.authenticationServices};
    case fic::identity::pam::PamProviderKind::PamPwquality:
    case fic::identity::pam::PamProviderKind::PamPasswdqc:
        return {fic::identity::pam::PamCapability::PasswordQuality,
                platform.passwordServices};
    case fic::identity::pam::PamProviderKind::PamPwhistory:
        return {fic::identity::pam::PamCapability::PasswordHistory,
                platform.passwordServices};
    default:
        return {fic::identity::pam::PamCapability::PasswordQuality, {}};
    }
}

} // namespace

RequiredPamEnforcementPolicy::RequiredPamEnforcementPolicy(
    const fic::platform::PamPlatformConfig& platformConfig)
    : PamPolicy(), platformConfig_(platformConfig) {
    this->policyName = "required_pam_enforcement";
    this->policyTypeValue = std::make_unique<RequiredPamPolicyTypeValue>();
}

bool RequiredPamEnforcementPolicy::applyPam(
    const std::string& expectedValue) {
    std::vector<fic::identity::pam::PamProviderKind> providers;
    std::string normalized;
    std::string error;
    if (!fic::identity::pam::parseRequiredPamProviders(
            expectedValue, providers, normalized, error)) {
        this->log("Invalid required PAM enforcement value: " + error,
                  logLevel::ERROR);
        return false;
    }

    fic::identity::pam::PamConfiguration configuration(platformConfig_);
    bool allEffective = true;
    for (const auto provider : providers) {
        const auto [capability, services] =
            capabilityAndServices(provider, platformConfig_);
        fic::identity::pam::PamCapabilityVerification verification;
        if (!fic::identity::pam::PamCapabilityVerifier::verify(
                configuration,
                platformConfig_,
                services,
                capability,
                provider,
                verification)) {
            allEffective = false;
            this->log(
                "Required PAM enforcement failed for " +
                    fic::identity::pam::pamProviderName(provider) + ": " +
                    fic::identity::pam::formatPamCapabilityVerification(
                        verification),
                logLevel::ERROR);
        } else {
            this->log(
                "Required PAM enforcement is effective for " +
                    fic::identity::pam::pamProviderName(provider),
                logLevel::INFO);
        }
    }
    return allEffective;
}
