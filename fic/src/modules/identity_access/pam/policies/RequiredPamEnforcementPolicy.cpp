#include "modules/identity_access/pam/policies/RequiredPamEnforcementPolicy.h"

#include "modules/identity_access/pam/PamCapabilityVerifier.h"
#include "modules/identity_access/pam/PamConfiguration.h"
#include "modules/identity_access/pam/PamPlatformComposition.h"
#include "modules/identity_access/pam/PamProviderCatalog.h"
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

} // namespace

RequiredPamEnforcementPolicy::RequiredPamEnforcementPolicy(
    const fic::platform::PamPlatformConfig& platformConfig)
    : PamPolicy(), platformConfig_(platformConfig) {
    this->policyName = "required_pam_enforcement";
    this->policyTypeValue = std::make_unique<RequiredPamPolicyTypeValue>();
    if (platformConfig_.passwordlessLoginControl.has_value()) {
        addRecommendedDependency(
            {"IDENTITY_ACCESS", "PAM", "disable_nopasswdlogin"});
    }
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
        const auto capability =
            fic::identity::pam::pamProviderDescriptor(provider).capability;
        const fic::platform::PamCapabilityConfig* configuredCapability = nullptr;
        const std::vector<std::string>* services = nullptr;
        if (!fic::identity::pam::resolveCapability(
                platformConfig_, capability, configuredCapability, services,
                error) || configuredCapability->provider != provider) {
            allEffective = false;
            this->log(
                "Required PAM provider is not part of the platform "
                "composition: " +
                    fic::identity::pam::pamProviderName(provider),
                logLevel::ERROR);
            continue;
        }
        fic::identity::pam::PamCapabilityVerification verification;
        if (!fic::identity::pam::PamCapabilityVerifier::verify(
                configuration,
                platformConfig_,
                *services,
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
