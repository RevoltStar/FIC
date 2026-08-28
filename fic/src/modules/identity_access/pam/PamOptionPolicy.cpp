#include "modules/identity_access/pam/PamOptionPolicy.h"

#include "modules/identity_access/pam/PamConfiguration.h"
#include "modules/identity_access/pam/PamCapabilityVerifier.h"
#include "modules/identity_access/pam/PamConfigFileTransaction.h"
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
    const auto& provider =
        fic::identity::pam::pamProviderDescriptor(capability->provider);
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
            capabilityVerification,
            fic::identity::pam::PamCapabilityVerificationMode::Structural)) {
        this->log(
            "PAM capability preflight failed for " + this->policyName +
                ": " + fic::identity::pam::formatPamCapabilityVerification(
                    capabilityVerification),
            logLevel::ERROR);
        return false;
    }
    const auto& inspection = capabilityVerification.inspection;
    const bool overridesValid =
        provider.grammar == fic::platform::PamConfigGrammar::Passwdqc
        ? true
        : binding->syntax ==
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
        if (provider.grammar == fic::platform::PamConfigGrammar::Passwdqc) {
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
    const auto setExpectedState = [&]
        (const fic::identity::pam::PamConfigFileTransaction::Writer& writer,
         std::string& stateError) {
        if (provider.grammar == fic::platform::PamConfigGrammar::Passwdqc) {
            return fic::identity::pam::PasswdqcConfigFile::setValue(
                capability->configPath, binding->option,
                nativeExpectedValue, stateError, writer);
        }
        return binding->syntax ==
                fic::identity::pam::PamNativeOptionSyntax::Assignment
            ? fic::identity::pam::PamOptionFile::setValue(
                  capability->configPath, binding->option,
                  nativeExpectedValue, stateError, writer)
            : fic::identity::pam::PamOptionFile::setFlag(
                  capability->configPath, binding->option,
                  expectedFlagEnabled, stateError, writer);
    };

    std::string currentError;
    fic::identity::pam::PamConfigFileSnapshot snapshot;
    const auto failAfterMutation = [&](const std::string& failure) {
        std::string diagnostic = failure;
        std::string rollbackError;
        if (!fic::identity::pam::PamConfigFileTransaction::rollback(
                snapshot, rollbackError)) {
            diagnostic += "; CRITICAL: PAM policy rollback failed: " +
                rollbackError + "; PAM configuration may be degraded";
        }
        this->log(diagnostic, logLevel::ERROR);
        return false;
    };
    if (!hasExpectedState(currentError)) {
        if (!fic::identity::pam::PamConfigFileTransaction::capture(
                capability->configPath, snapshot, error)) {
            this->log(
                "Could not snapshot PAM option for " + this->policyName +
                    ": " + error,
                logLevel::ERROR);
            return false;
        }
        if (!fic::identity::pam::PamConfigFileTransaction::mutate(
                snapshot,
                [&](const auto& writer, std::string& mutationError) {
                    return setExpectedState(writer, mutationError);
                },
                error)) {
            return failAfterMutation(
                "Could not update PAM option for " + this->policyName +
                    ": " + error);
        }
    }

    if (!hasExpectedState(error)) {
        return failAfterMutation(
            "PAM option postcondition failed for " + this->policyName +
                ": " + error);
    }
    if (binding->syntax == fic::identity::pam::PamNativeOptionSyntax::Flag &&
        !expectedFlagEnabled &&
        !fic::identity::pam::PamOptionFile::verifyNoActiveDirectives(
            capability->configPath,
            binding->conflictingOptionsWhenDisabled, error)) {
        return failAfterMutation(
            "PAM flag dependency postcondition failed for " +
                this->policyName + ": " + error);
    }

    std::size_t verifiedServiceCount = 0;
    if (!verifyPostMutationPamState(
            *capability, *services, *binding, nativeExpectedValue,
            expectedFlagEnabled, verifiedServiceCount, error)) {
        return failAfterMutation(
            "PAM graph postcondition failed for " + this->policyName +
                ": " + error);
    }

    this->log(
        "PAM policy " + this->policyName + " is effective for " +
            std::to_string(verifiedServiceCount) +
            " configured services",
        logLevel::INFO);
    return true;
}

bool PamOptionPolicy::verifyPostMutationPamState(
    const fic::platform::PamCapabilityConfig& capability,
    const std::vector<std::string>& services,
    const fic::identity::pam::PamProviderPolicyBinding& binding,
    const std::string& nativeExpectedValue,
    bool expectedFlagEnabled,
    std::size_t& verifiedServiceCount,
    std::string& error) const
{
    fic::identity::pam::PamConfiguration verification(platformConfig_);
    fic::identity::pam::PamCapabilityVerification verifiedCapability;
    if (!fic::identity::pam::PamCapabilityVerifier::verify(
            verification, platformConfig_, services, capability.capability,
            capability.provider, verifiedCapability)) {
        error = fic::identity::pam::formatPamCapabilityVerification(
            verifiedCapability);
        return false;
    }
    const bool overridesValid = binding.syntax ==
            fic::identity::pam::PamNativeOptionSyntax::Assignment
        ? fic::identity::pam::PamProviderInspector::verifyOptionOverrides(
              verifiedCapability.inspection, capability.configPath.string(),
              binding.option, nativeExpectedValue, error)
        : fic::identity::pam::PamProviderInspector::verifyFlagOverrides(
              verifiedCapability.inspection, capability.configPath.string(),
              binding.option, expectedFlagEnabled, error,
              binding.conflictingOptionsWhenDisabled);
    if (!overridesValid) {
        return false;
    }
    verifiedServiceCount = verifiedCapability.inspection.services.size();
    error.clear();
    return true;
}
