#include "modules/identity_access/submodules/pam/PamOptionPolicy.h"

#include "modules/identity_access/submodules/pam/PamConfiguration.h"
#include "modules/identity_access/submodules/pam/PamOptionFile.h"

#include <utility>

PamOptionPolicy::PamOptionPolicy(
    fic::platform::PamPlatformConfig platformConfig,
    fic::identity::pam::PamCapability capability,
    fic::identity::pam::PamProviderKind provider,
    std::filesystem::path optionFile,
    std::string option,
    std::vector<std::string> services,
    PamOptionSyntax syntax)
    : PamPolicy(),
      platformConfig_(std::move(platformConfig)),
      capability_(capability),
      provider_(provider),
      optionFile_(std::move(optionFile)),
      option_(std::move(option)),
      services_(std::move(services)),
      syntax_(syntax) {
}

bool PamOptionPolicy::applyPam(const std::string& expectedValue) {
    bool expectedFlagEnabled = false;
    if (syntax_ == PamOptionSyntax::Flag) {
        if (expectedValue == "yes") {
            expectedFlagEnabled = true;
        } else if (expectedValue != "no") {
            this->log(
                "Invalid PAM flag policy value for " + this->policyName +
                    ": " + expectedValue,
                logLevel::ERROR);
            return false;
        }
    }

    fic::identity::pam::PamConfiguration configuration(platformConfig_);
    fic::identity::pam::PamProviderInspection inspection;
    std::string error;
    if (!fic::identity::pam::PamProviderInspector::inspect(
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
    if (!fic::identity::pam::PamProviderInspector::verifyProviderFiles(
            inspection, platformConfig_.moduleDirectories, error)) {
        this->log(
            "PAM provider file verification failed for " + this->policyName +
                ": " + error,
            logLevel::ERROR);
        return false;
    }
    if (!fic::identity::pam::PamProviderInspector::verifyConfigurationFiles(
            inspection, error)) {
        this->log(
            "PAM configuration file verification failed for " +
                this->policyName + ": " + error,
            logLevel::ERROR);
        return false;
    }
    const bool overridesValid = syntax_ == PamOptionSyntax::Assignment
        ? fic::identity::pam::PamProviderInspector::verifyOptionOverrides(
              inspection, optionFile_.string(), option_, expectedValue, error)
        : fic::identity::pam::PamProviderInspector::verifyFlagOverrides(
              inspection, optionFile_.string(), option_,
              expectedFlagEnabled, error);
    if (!overridesValid) {
        this->log(
            "PAM option override preflight failed for " + this->policyName +
                ": " + error,
            logLevel::ERROR);
        return false;
    }

    const auto hasExpectedState = [&](std::string& stateError) {
        return syntax_ == PamOptionSyntax::Assignment
            ? fic::identity::pam::PamOptionFile::hasOnlyValue(
                  optionFile_, option_, expectedValue, stateError)
            : fic::identity::pam::PamOptionFile::hasFlag(
                  optionFile_, option_, expectedFlagEnabled, stateError);
    };
    const auto setExpectedState = [&](std::string& stateError) {
        return syntax_ == PamOptionSyntax::Assignment
            ? fic::identity::pam::PamOptionFile::setValue(
                  optionFile_, option_, expectedValue, stateError)
            : fic::identity::pam::PamOptionFile::setFlag(
                  optionFile_, option_, expectedFlagEnabled, stateError);
    };

    std::string currentError;
    if (!hasExpectedState(currentError)) {
        if (!setExpectedState(error)) {
            this->log(
                "Could not update PAM option for " + this->policyName +
                    ": " + error,
                logLevel::ERROR);
            return false;
        }
    }

    if (!hasExpectedState(error)) {
        this->log(
            "PAM option postcondition failed for " + this->policyName +
                ": " + error,
            logLevel::ERROR);
        return false;
    }

    fic::identity::pam::PamConfiguration verification(platformConfig_);
    fic::identity::pam::PamProviderInspection verifiedInspection;
    if (!fic::identity::pam::PamProviderInspector::inspect(
            verification,
            services_,
            capability_,
            provider_,
            verifiedInspection,
            error) ||
        !fic::identity::pam::PamProviderInspector::verifyProviderFiles(
            verifiedInspection, platformConfig_.moduleDirectories, error) ||
        !fic::identity::pam::PamProviderInspector::verifyConfigurationFiles(
            verifiedInspection, error) ||
        !(syntax_ == PamOptionSyntax::Assignment
              ? fic::identity::pam::PamProviderInspector::
                    verifyOptionOverrides(
                        verifiedInspection, optionFile_.string(), option_,
                        expectedValue, error)
              : fic::identity::pam::PamProviderInspector::
                    verifyFlagOverrides(
                        verifiedInspection, optionFile_.string(), option_,
                        expectedFlagEnabled, error))) {
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
