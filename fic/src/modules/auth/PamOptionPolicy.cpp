#include "modules/auth/PamOptionPolicy.h"

#include "modules/auth/pam/PamConfiguration.h"
#include "modules/auth/pam/PamOptionFile.h"

#include <utility>

PamOptionPolicy::PamOptionPolicy(
    fic::platform::PamPlatformConfig platformConfig,
    fic::auth::PamCapability capability,
    fic::auth::PamProviderKind provider,
    std::filesystem::path optionFile,
    std::string option,
    std::vector<std::string> services)
    : Auth(),
      platformConfig_(std::move(platformConfig)),
      capability_(capability),
      provider_(provider),
      optionFile_(std::move(optionFile)),
      option_(std::move(option)),
      services_(std::move(services)) {
}

bool PamOptionPolicy::apply() {
    const std::optional<std::string> value = this->getValue();
    if (!value.has_value()) {
        return false;
    }

    fic::auth::PamConfiguration configuration(platformConfig_);
    fic::auth::PamProviderInspection inspection;
    std::string error;
    if (!fic::auth::PamProviderInspector::inspect(
            configuration,
            services_,
            capability_,
            provider_,
            inspection,
            error)) {
        this->log(
            "PAM provider preflight failed for " + this->policyName +
                ": " + error,
            logLevel::ERROR);
        return false;
    }
    if (!fic::auth::PamProviderInspector::verifyProviderFiles(
            inspection, platformConfig_.moduleDirectories, error)) {
        this->log(
            "PAM provider file verification failed for " + this->policyName +
                ": " + error,
            logLevel::ERROR);
        return false;
    }
    if (!fic::auth::PamProviderInspector::verifyConfigurationFiles(
            inspection, error)) {
        this->log(
            "PAM configuration file verification failed for " +
                this->policyName + ": " + error,
            logLevel::ERROR);
        return false;
    }
    if (!fic::auth::PamProviderInspector::verifyOptionOverrides(
            inspection,
            optionFile_.string(),
            option_,
            *value,
            error)) {
        this->log(
            "PAM option override preflight failed for " + this->policyName +
                ": " + error,
            logLevel::ERROR);
        return false;
    }

    std::string currentError;
    if (!fic::auth::PamOptionFile::hasOnlyValue(
            optionFile_, option_, *value, currentError)) {
        if (!fic::auth::PamOptionFile::setValue(
                optionFile_, option_, *value, error)) {
            this->log(
                "Could not update PAM option for " + this->policyName +
                    ": " + error,
                logLevel::ERROR);
            return false;
        }
    }

    if (!fic::auth::PamOptionFile::hasOnlyValue(
            optionFile_, option_, *value, error)) {
        this->log(
            "PAM option postcondition failed for " + this->policyName +
                ": " + error,
            logLevel::ERROR);
        return false;
    }

    fic::auth::PamConfiguration verification(platformConfig_);
    fic::auth::PamProviderInspection verifiedInspection;
    if (!fic::auth::PamProviderInspector::inspect(
            verification,
            services_,
            capability_,
            provider_,
            verifiedInspection,
            error) ||
        !fic::auth::PamProviderInspector::verifyProviderFiles(
            verifiedInspection, platformConfig_.moduleDirectories, error) ||
        !fic::auth::PamProviderInspector::verifyConfigurationFiles(
            verifiedInspection, error) ||
        !fic::auth::PamProviderInspector::verifyOptionOverrides(
            verifiedInspection,
            optionFile_.string(),
            option_,
            *value,
            error)) {
        this->log(
            "PAM graph postcondition failed for " + this->policyName +
                ": " + error,
            logLevel::ERROR);
        return false;
    }

    this->log(
        "PAM policy " + this->policyName + " is effective for " +
            std::to_string(verifiedInspection.services.size()) +
            " configured services",
        logLevel::INFO);
    return true;
}
