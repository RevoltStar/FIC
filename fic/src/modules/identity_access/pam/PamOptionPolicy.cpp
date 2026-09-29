#include "modules/identity_access/pam/PamOptionPolicy.h"

#include "modules/identity_access/pam/PamConfiguration.h"
#include "modules/identity_access/pam/PamCapabilityVerifier.h"
#include "modules/identity_access/pam/PamConfigFileTransaction.h"
#include "modules/identity_access/pam/PamOptionFile.h"
#include "modules/identity_access/pam/PamPlatformComposition.h"
#include "modules/identity_access/pam/PamProviderCatalog.h"
#include "modules/identity_access/pam/PamProviderConfigFile.h"
#include "modules/identity_access/pam/PamProviderManagedEntryExecutor.h"
#include "modules/identity_access/pam/PamProviderModuleArguments.h"
#include "modules/identity_access/pam/PamProviderSemanticVerifier.h"
#include "modules/identity_access/pam/policies/PamCapabilityActivationPolicy.h"
#include "rollback/DaemonMutationJournal.h"

#include <utility>

PamOptionPolicy::PamOptionPolicy(
    fic::platform::PamPlatformConfig platformConfig,
    fic::platform::PamPolicyFeature feature)
    : PamPolicy(),
      platformConfig_(std::move(platformConfig)),
      feature_(feature) {
    const auto capability =
        fic::identity::pam::pamPolicyCapability(feature_);
    if (fic::identity::pam::pamPolicySupport(platformConfig_, feature_) ==
        fic::platform::PamPolicySupport::RequiresTopologyActivation) {
        addRecommendedDependency(
            {"IDENTITY_ACCESS", "PAM",
             pamCapabilityActivationPolicyName(capability)});
    }
    if (capability ==
            fic::platform::PamCapability::AuthenticationLockout &&
        platformConfig_.passwordlessLoginControl.has_value()) {
        addRecommendedDependency(
            {"IDENTITY_ACCESS", "PAM", "disable_nopasswdlogin"});
    }
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

    // Step 7B routing: the supported faillock scalar assignment contract
    // goes through the journal-backed managed provider block executor
    // instead of the legacy replace-all/snapshot writer.
    if (fic::identity::pam::usesPamProviderManagedEntry(
            provider, *capability, *binding, feature_)) {
        return this->applyManagedProviderEntry(
            *capability, *services, *binding, nativeExpectedValue);
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
    const bool moduleArguments = capability->configurationMode ==
        fic::platform::PamCapabilityConfigurationMode::ModuleArguments;
    const bool overridesValid = binding->syntax ==
            fic::identity::pam::PamNativeOptionSyntax::Assignment
        ? fic::identity::pam::PamProviderSemanticVerifier::canApplyOption(
              inspection, *capability, binding->option,
              nativeExpectedValue, error)
        : fic::identity::pam::PamProviderSemanticVerifier::canApplyFlag(
              inspection, *capability, binding->option,
              expectedFlagEnabled,
              binding->conflictingOptionsWhenDisabled, error);
    if (!overridesValid) {
        this->log(
            "PAM option override preflight failed for " + this->policyName +
                ": " + error,
            logLevel::ERROR);
        return false;
    }
    if (!moduleArguments &&
        binding->syntax == fic::identity::pam::PamNativeOptionSyntax::Flag &&
        !expectedFlagEnabled &&
        !fic::identity::pam::PamProviderConfigFile::verifyNoActiveDirectives(
            provider,
            capability->configPath,
            binding->conflictingOptionsWhenDisabled, error)) {
        this->log(
            "PAM flag dependency preflight failed for " +
                this->policyName + ": " + error,
            logLevel::ERROR);
        return false;
    }

    fic::identity::pam::PamRule moduleArgumentRule;
    if (moduleArguments &&
        !fic::identity::pam::PamProviderModuleArguments::uniqueRule(
            inspection, moduleArgumentRule, error)) {
        this->log(
            "PAM module-argument mutation preflight failed for " +
                this->policyName + ": " + error,
            logLevel::ERROR);
        return false;
    }
    const auto hasExpectedState = [&](std::string& stateError) {
        if (!moduleArguments) {
            return fic::identity::pam::PamProviderConfigFile::hasExpectedState(
                provider, *binding, capability->configPath,
                nativeExpectedValue, expectedFlagEnabled, stateError);
        }
        fic::identity::pam::PamConfiguration current(platformConfig_);
        fic::identity::pam::PamCapabilityVerification currentVerification;
        if (!fic::identity::pam::PamCapabilityVerifier::verify(
                current, platformConfig_, *services, capability->capability,
                capability->provider, currentVerification,
                fic::identity::pam::PamCapabilityVerificationMode::Structural)) {
            stateError = fic::identity::pam::formatPamCapabilityVerification(
                currentVerification);
            return false;
        }
        return fic::identity::pam::PamProviderModuleArguments::hasExpectedState(
            currentVerification.inspection, *binding, nativeExpectedValue,
            expectedFlagEnabled, stateError);
    };
    const auto setExpectedConfigState = [&]
        (const fic::identity::pam::PamConfigFileTransaction::Writer& writer,
         std::string& stateError) {
        return fic::identity::pam::PamProviderConfigFile::setExpectedState(
            provider, *binding, capability->configPath,
            nativeExpectedValue, expectedFlagEnabled, stateError, writer);
    };

    std::string currentError;
    fic::identity::pam::PamConfigFileSnapshot snapshot;
    const auto failAfterMutation = [&](const std::string& failure) {
        std::string diagnostic = failure;
        std::string rollbackError;
        if (snapshot.state !=
                fic::identity::pam::PamConfigFileTransactionState::Uninitialized &&
            !fic::identity::pam::PamConfigFileTransaction::rollback(
                snapshot, rollbackError)) {
            diagnostic += "; CRITICAL: PAM policy rollback failed: " +
                rollbackError + "; PAM configuration may be degraded";
        }
        this->log(diagnostic, logLevel::ERROR);
        return false;
    };
    if (!hasExpectedState(currentError)) {
        const std::filesystem::path mutationPath = moduleArguments
            ? moduleArgumentRule.source
            : capability->configPath;
        if (!fic::identity::pam::PamConfigFileTransaction::capture(
                mutationPath, snapshot, error)) {
            this->log(
                "Could not snapshot PAM option for " + this->policyName +
                    ": " + error,
                logLevel::ERROR);
            return false;
        }
        const bool mutated = moduleArguments
            ? fic::identity::pam::PamProviderModuleArguments::setExpectedState(
                  capability->provider, moduleArgumentRule, *binding,
                  nativeExpectedValue, expectedFlagEnabled, snapshot, error)
            : fic::identity::pam::PamConfigFileTransaction::mutate(
                  snapshot,
                  [&](const auto& writer, std::string& mutationError) {
                      return setExpectedConfigState(writer, mutationError);
                  },
                  error);
        if (!mutated) {
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
    if (!moduleArguments &&
        binding->syntax == fic::identity::pam::PamNativeOptionSyntax::Flag &&
        !expectedFlagEnabled &&
        !fic::identity::pam::PamProviderConfigFile::verifyNoActiveDirectives(
            provider,
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

bool PamOptionPolicy::applyManagedProviderEntry(
    const fic::platform::PamCapabilityConfig& capability,
    const std::vector<std::string>& services,
    const fic::identity::pam::PamProviderPolicyBinding& binding,
    const std::string& nativeExpectedValue) {
    // Structural preflight (same semantics as the legacy path): the
    // provider must be active and structurally sound BEFORE any journal
    // transaction is prepared.
    std::string error;
    fic::identity::pam::PamConfiguration configuration(platformConfig_);
    fic::identity::pam::PamCapabilityVerification preflight;
    if (!fic::identity::pam::PamCapabilityVerifier::verify(
            configuration, platformConfig_, services, capability.capability,
            capability.provider, preflight,
            fic::identity::pam::PamCapabilityVerificationMode::Structural)) {
        this->log(
            "PAM capability preflight failed for " + this->policyName +
                ": " +
                fic::identity::pam::formatPamCapabilityVerification(
                    preflight),
            logLevel::ERROR);
        return false;
    }
    if (!fic::identity::pam::PamProviderSemanticVerifier::canApplyOption(
            preflight.inspection, capability, binding.option,
            nativeExpectedValue, error)) {
        this->log(
            "PAM option override preflight failed for " + this->policyName +
                ": " + error,
            logLevel::ERROR);
        return false;
    }

    // Journal provenance is MANDATORY on the managed path (fail closed):
    // a physical mutation without durable Prepared provenance would
    // destroy rollback ownership. There is NO legacy-writer fallback.
    auto* journal =
        fic::rollback::DaemonMutationJournal::instance().tryGet(error);
    if (journal == nullptr) {
        this->log(
            "PAM mutation journal is not usable for " + this->policyName +
                " (fail closed): " + error,
            logLevel::ERROR);
        return false;
    }

    const auto& provider =
        fic::identity::pam::pamProviderDescriptor(capability.provider);
    fic::identity::pam::PamProviderManagedEntryRequest request;
    request.policyName = this->policyName;
    request.provider = capability.provider;
    request.providerName = provider.name;
    request.managedKey = binding.option;
    request.nativeValue = nativeExpectedValue;
    request.configPath = capability.configPath;
    // faillock.conf scalar assignments have last-wins semantics → EOF.
    request.placement =
        fic::identity::pam::PamProviderBlockPlacementRequest::End;
    request.absentDecision =
        fic::identity::pam::pamProviderAbsentContainerDecision(provider);

    // Semantic postcondition: reuse the existing verification pipeline
    // (PamCapabilityVerifier + PamProviderSemanticVerifier over the
    // configured services); the executor runs it before every Applied
    // transition. The expected native value is PARAMETERIZED: the executor
    // passes the durable journal target while completing an unresolved
    // Prepared transaction and the current desired value otherwise — the
    // captured `nativeExpectedValue` must never be used for all phases.
    auto semantic = [&](const std::string& expectedNativeValue,
                        std::string& semanticError) {
        std::size_t verifiedServiceCount = 0;
        return this->verifyPostMutationPamState(
            capability, services, binding, expectedNativeValue,
            /*expectedFlagEnabled=*/false, verifiedServiceCount,
            semanticError);
    };

    auto outcome =
        fic::identity::pam::PamProviderManagedEntryOutcome::AppliedNoOp;
    if (!fic::identity::pam::PamProviderManagedEntryExecutor::apply(
            request, *journal, semantic, outcome, error)) {
        this->log(
            "PAM managed provider entry apply failed for " +
                this->policyName + ": " + error,
            logLevel::ERROR);
        return false;
    }
    this->log(
        std::string("PAM policy ") + this->policyName +
            (outcome ==
                    fic::identity::pam::PamProviderManagedEntryOutcome::
                        AppliedNoOp
                ? " is proven effective on the managed provider block "
                  "(no-op)"
                : " applied through the managed provider block"),
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
        ? fic::identity::pam::PamProviderSemanticVerifier::verifyOption(
              verifiedCapability.inspection, capability,
              binding.option, nativeExpectedValue, error)
        : fic::identity::pam::PamProviderSemanticVerifier::verifyFlag(
              verifiedCapability.inspection, capability,
              binding.option, expectedFlagEnabled,
              binding.conflictingOptionsWhenDisabled, error);
    if (!overridesValid) {
        return false;
    }
    verifiedServiceCount = verifiedCapability.inspection.services.size();
    error.clear();
    return true;
}
