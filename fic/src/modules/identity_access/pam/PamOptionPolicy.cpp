#include "modules/identity_access/pam/PamOptionPolicy.h"

#include "modules/identity_access/pam/PamConfiguration.h"
#include "modules/identity_access/pam/PamCapabilityVerifier.h"
#include "modules/identity_access/pam/PamOptionFile.h"

#include <utility>

PamOptionPolicy::PamOptionPolicy(
    fic::platform::PamPlatformConfig platformConfig,
    fic::identity::pam::PamCapability capability,
    fic::identity::pam::PamProviderKind provider,
    std::filesystem::path optionFile,
    std::string option,
    std::vector<std::string> services,
    PamOptionSyntax syntax,
    std::vector<std::string> conflictingOptionsWhenFlagDisabled,
    fic::identity::pam::PamOptionValueEncoding valueEncoding)
    : PamPolicy(),
      platformConfig_(std::move(platformConfig)),
      capability_(capability),
      provider_(provider),
      optionFile_(std::move(optionFile)),
      option_(std::move(option)),
      services_(std::move(services)),
      syntax_(syntax),
      conflictingOptionsWhenFlagDisabled_(
          std::move(conflictingOptionsWhenFlagDisabled)),
      valueEncoding_(valueEncoding) {
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

    std::string nativeExpectedValue;
    std::string error;
    if (syntax_ == PamOptionSyntax::Assignment &&
        !fic::identity::pam::PamOptionValueCodec::encode(
            valueEncoding_, expectedValue, nativeExpectedValue, error)) {
        this->log(
            "Invalid PAM option policy value for " + this->policyName +
                ": " + error,
            logLevel::ERROR);
        return false;
    }

    fic::identity::pam::PamConfiguration configuration(platformConfig_);
    fic::identity::pam::PamCapabilityVerification capabilityVerification;
    if (!fic::identity::pam::PamCapabilityVerifier::verify(
            configuration,
            platformConfig_,
            services_,
            capability_,
            provider_,
            capabilityVerification)) {
        this->log(
            "PAM capability preflight failed for " + this->policyName +
                ": " + fic::identity::pam::formatPamCapabilityVerification(
                    capabilityVerification),
            logLevel::ERROR);
        return false;
    }
    const auto& inspection = capabilityVerification.inspection;
    const bool overridesValid = syntax_ == PamOptionSyntax::Assignment
        ? fic::identity::pam::PamProviderInspector::verifyOptionOverrides(
              inspection, optionFile_.string(), option_, nativeExpectedValue,
              error)
        : fic::identity::pam::PamProviderInspector::verifyFlagOverrides(
              inspection, optionFile_.string(), option_,
              expectedFlagEnabled, error,
              conflictingOptionsWhenFlagDisabled_);
    if (!overridesValid) {
        this->log(
            "PAM option override preflight failed for " + this->policyName +
                ": " + error,
            logLevel::ERROR);
        return false;
    }
    if (syntax_ == PamOptionSyntax::Flag && !expectedFlagEnabled &&
        !fic::identity::pam::PamOptionFile::verifyNoActiveDirectives(
            optionFile_, conflictingOptionsWhenFlagDisabled_, error)) {
        this->log(
            "PAM flag dependency preflight failed for " +
                this->policyName + ": " + error,
            logLevel::ERROR);
        return false;
    }

    const auto hasExpectedState = [&](std::string& stateError) {
        return syntax_ == PamOptionSyntax::Assignment
            ? fic::identity::pam::PamOptionFile::hasOnlyValue(
                  optionFile_, option_, nativeExpectedValue, stateError)
            : fic::identity::pam::PamOptionFile::hasFlag(
                  optionFile_, option_, expectedFlagEnabled, stateError);
    };
    const auto setExpectedState = [&](std::string& stateError) {
        return syntax_ == PamOptionSyntax::Assignment
            ? fic::identity::pam::PamOptionFile::setValue(
                  optionFile_, option_, nativeExpectedValue, stateError)
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
    if (syntax_ == PamOptionSyntax::Flag && !expectedFlagEnabled &&
        !fic::identity::pam::PamOptionFile::verifyNoActiveDirectives(
            optionFile_, conflictingOptionsWhenFlagDisabled_, error)) {
        this->log(
            "PAM flag dependency postcondition failed for " +
                this->policyName + ": " + error,
            logLevel::ERROR);
        return false;
    }

    fic::identity::pam::PamConfiguration verification(platformConfig_);
    fic::identity::pam::PamCapabilityVerification verifiedCapability;
    if (!fic::identity::pam::PamCapabilityVerifier::verify(
            verification,
            platformConfig_,
            services_,
            capability_,
            provider_,
            verifiedCapability) ||
        !(syntax_ == PamOptionSyntax::Assignment
              ? fic::identity::pam::PamProviderInspector::
                    verifyOptionOverrides(
                        verifiedCapability.inspection,
                        optionFile_.string(), option_,
                        nativeExpectedValue, error)
              : fic::identity::pam::PamProviderInspector::
                    verifyFlagOverrides(
                        verifiedCapability.inspection,
                        optionFile_.string(), option_,
                        expectedFlagEnabled, error,
                        conflictingOptionsWhenFlagDisabled_))) {
        if (!verifiedCapability.detail.empty() &&
            verifiedCapability.state !=
                fic::identity::pam::PamEnforcementState::Effective) {
            error = fic::identity::pam::formatPamCapabilityVerification(
                verifiedCapability);
        }
        this->log(
            "PAM graph postcondition failed for " + this->policyName +
                ": " + error,
            logLevel::ERROR);
        return false;
    }

    this->log(
        "PAM policy " + this->policyName + " is effective for " +
            std::to_string(
                verifiedCapability.inspection.services.size()) +
            " configured services",
        logLevel::INFO);
    return true;
}
