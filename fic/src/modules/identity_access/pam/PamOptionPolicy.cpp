#include "modules/identity_access/pam/PamOptionPolicy.h"

#include "modules/identity_access/pam/PamConfiguration.h"
#include "modules/identity_access/pam/PamCapabilityVerifier.h"
#include "modules/identity_access/pam/PamOptionFile.h"
#include "modules/identity_access/pam/PamPlatformComposition.h"
#include "modules/identity_access/pam/PamProviderCatalog.h"
#include "modules/identity_access/pam/PasswdqcConfigFile.h"

#include <utility>

PamOptionPolicy::PamOptionPolicy(
    fic::platform::PamPlatformConfig platformConfig,
    fic::platform::PamPolicyFeature feature)
    : PamPolicy(),
      platformConfig_(std::move(platformConfig)),
      feature_(feature) {
}

bool PamOptionPolicy::applyPam(const std::string& expectedValue) {
    const fic::platform::PamCapabilityConfig* capability = nullptr;
    const std::vector<std::string>* services = nullptr;
    std::string error;
    if (!fic::identity::pam::resolveCapability(
            platformConfig_,
            fic::identity::pam::pamPolicyCapability(feature_),
            capability, services, error)) {
        this->log("PAM platform composition failed for " +
                      this->policyName + ": " + error,
                  logLevel::ERROR);
        return false;
    }
    const auto* binding = fic::identity::pam::pamProviderPolicyBinding(
        capability->provider, feature_);
    if (binding == nullptr) {
        this->log("PAM provider does not support policy " + this->policyName,
                  logLevel::ERROR);
        return false;
    }
    bool expectedFlagEnabled = false;
    if (binding->syntax ==
        fic::identity::pam::PamNativeOptionSyntax::Flag) {
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
    if (binding->syntax ==
            fic::identity::pam::PamNativeOptionSyntax::Assignment &&
        !fic::identity::pam::encodePamNativeValue(
            binding->encoding, expectedValue, nativeExpectedValue, error)) {
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
            *services,
            capability->capability,
            capability->provider,
            capabilityVerification)) {
        this->log(
            "PAM capability preflight failed for " + this->policyName +
                ": " + fic::identity::pam::formatPamCapabilityVerification(
                    capabilityVerification),
            logLevel::ERROR);
        return false;
    }
    const auto& inspection = capabilityVerification.inspection;
    const bool overridesValid = binding->syntax ==
            fic::identity::pam::PamNativeOptionSyntax::Assignment
        ? fic::identity::pam::PamProviderInspector::verifyOptionOverrides(
              inspection, capability->configPath.string(), binding->option,
              nativeExpectedValue, error)
        : fic::identity::pam::PamProviderInspector::verifyFlagOverrides(
              inspection, capability->configPath.string(), binding->option,
              expectedFlagEnabled, error,
              binding->conflictingOptionsWhenDisabled);
    if (!overridesValid) {
        this->log(
            "PAM option override preflight failed for " + this->policyName +
                ": " + error,
            logLevel::ERROR);
        return false;
    }
    if (binding->syntax == fic::identity::pam::PamNativeOptionSyntax::Flag &&
        !expectedFlagEnabled &&
        !fic::identity::pam::PamOptionFile::verifyNoActiveDirectives(
            capability->configPath,
            binding->conflictingOptionsWhenDisabled, error)) {
        this->log(
            "PAM flag dependency preflight failed for " +
                this->policyName + ": " + error,
            logLevel::ERROR);
        return false;
    }

    const auto hasExpectedState = [&](std::string& stateError) {
        if (capability->grammar == fic::platform::PamConfigGrammar::Passwdqc) {
            return fic::identity::pam::PasswdqcConfigFile::hasOnlyValue(
                capability->configPath, binding->option,
                nativeExpectedValue, stateError);
        }
        return binding->syntax ==
                fic::identity::pam::PamNativeOptionSyntax::Assignment
            ? fic::identity::pam::PamOptionFile::hasOnlyValue(
                  capability->configPath, binding->option,
                  nativeExpectedValue, stateError)
            : fic::identity::pam::PamOptionFile::hasFlag(
                  capability->configPath, binding->option,
                  expectedFlagEnabled, stateError);
    };
    const auto setExpectedState = [&](std::string& stateError) {
        if (capability->grammar == fic::platform::PamConfigGrammar::Passwdqc) {
            return fic::identity::pam::PasswdqcConfigFile::setValue(
                capability->configPath, binding->option,
                nativeExpectedValue, stateError);
        }
        return binding->syntax ==
                fic::identity::pam::PamNativeOptionSyntax::Assignment
            ? fic::identity::pam::PamOptionFile::setValue(
                  capability->configPath, binding->option,
                  nativeExpectedValue, stateError)
            : fic::identity::pam::PamOptionFile::setFlag(
                  capability->configPath, binding->option,
                  expectedFlagEnabled, stateError);
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
    if (binding->syntax == fic::identity::pam::PamNativeOptionSyntax::Flag &&
        !expectedFlagEnabled &&
        !fic::identity::pam::PamOptionFile::verifyNoActiveDirectives(
            capability->configPath,
            binding->conflictingOptionsWhenDisabled, error)) {
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
            *services,
            capability->capability,
            capability->provider,
            verifiedCapability) ||
        !(binding->syntax ==
                  fic::identity::pam::PamNativeOptionSyntax::Assignment
              ? fic::identity::pam::PamProviderInspector::
                    verifyOptionOverrides(
                        verifiedCapability.inspection,
                        capability->configPath.string(), binding->option,
                        nativeExpectedValue, error)
              : fic::identity::pam::PamProviderInspector::
                    verifyFlagOverrides(
                        verifiedCapability.inspection,
                        capability->configPath.string(), binding->option,
                        expectedFlagEnabled, error,
                        binding->conflictingOptionsWhenDisabled))) {
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
