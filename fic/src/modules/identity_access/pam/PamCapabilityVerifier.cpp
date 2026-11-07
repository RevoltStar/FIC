#include "modules/identity_access/pam/PamCapabilityVerifier.h"

#include "modules/identity_access/pam/PamPlatformComposition.h"
#include "modules/identity_access/pam/PamManagedPasswordSlots.h"
#include "modules/identity_access/pam/PamProviderSemanticVerifier.h"

#include <algorithm>

namespace fic::identity::pam {

bool PamCapabilityVerifier::verifyPasswordDomain(
    const fic::platform::PamPlatformConfig& platformConfig,
    PamCapability requiredCapability, bool qualityRequested,
    bool historyRequested, bool after, std::string& proofError,
    const StructuralProof& customProof) {
    const auto verifyFresh = [&](const fic::platform::PamCapabilityConfig& config,
                                 const std::vector<std::string>& services,
                                 PamCapabilityVerification& proof) {
        if (customProof) return customProof(config, services, proof);
        PamConfiguration configuration(platformConfig);
        return verify(configuration, platformConfig, services, config.capability,
            config.provider, proof, PamCapabilityVerificationMode::Structural);
    };
    for (const auto member : {fic::platform::PamCapability::PasswordQuality,
                              fic::platform::PamCapability::PasswordHistory}) {
        const fic::platform::PamCapabilityConfig* config = nullptr;
        const std::vector<std::string>* memberServices = nullptr;
        if (!fic::identity::pam::resolveCapability(platformConfig, member,
                config, memberServices, proofError)) return false;
        if (config->topology != fic::platform::PamTopologyStrategyKind::PamAuthUpdate)
            continue;
        const bool required = member == requiredCapability ||
            (member == fic::platform::PamCapability::PasswordQuality
                ? qualityRequested : historyRequested);
        fic::identity::pam::PamCapabilityVerification proof;
        if (!verifyFresh(*config, *memberServices, proof)) {
            // An Inactive result can describe only the FIRST missing
            // service. Prove absence across the whole existing scope;
            // a partially connected mechanism is not absent.
            const auto isAbsent = [&](const auto& value) {
                return value.state == fic::identity::pam::PamEnforcementState::Inactive ||
                    (!required && value.state ==
                        fic::identity::pam::PamEnforcementState::Missing);
            };
            bool absent = (!after || !required) && isAbsent(proof);
            fic::identity::pam::PamConfiguration configuration(platformConfig);
            std::vector<std::string> existing;
            if (absent && !configuration.existingServices(*memberServices, existing, proofError))
                absent = false;
            for (const auto& service : existing) {
                fic::identity::pam::PamCapabilityVerification perService;
                if (verifyFresh(*config, {service}, perService) || !isAbsent(perService)) {
                    absent = false;
                    break;
                }
            }
            if (!absent) {
                proofError = (member == PamCapability::PasswordQuality ? "enable_password_quality" : "enable_password_history") + std::string(": ") +
                    fic::identity::pam::formatPamCapabilityVerification(proof);
                return false;
            }
        } else if (member == fic::platform::PamCapability::PasswordHistory &&
            std::any_of(proof.inspection.providerRules.begin(), proof.inspection.providerRules.end(),
                [](const auto& rule) {
                    const auto name = rule.source.filename();
                    return name != fic::identity::pam::PamManagedPasswordSlots::historyNormalSlot().fileName &&
                        name != fic::identity::pam::PamManagedPasswordSlots::historyInitialSlot().fileName;
                })) {
            // C2 supports foreign quality, but has no foreign-history
            // state. Its own full slot grammar/ownership is proven by
            // the coordinator, never inferred from this file name.
            proofError = "foreign password history is outside the supported C2 topology";
            return false;
        }
    }
    return true;
}

bool PamCapabilityVerifier::verify(
    PamConfiguration& configuration,
    const fic::platform::PamPlatformConfig& platformConfig,
    const std::vector<std::string>& services,
    PamCapability capability,
    PamProviderKind provider,
    PamCapabilityVerification& verification,
    PamCapabilityVerificationMode mode) {
    verification = PamCapabilityVerification{};
    PamProviderInspectionFailure inspectionFailure =
        PamProviderInspectionFailure::None;
    std::string error;
    if (!PamProviderInspector::inspect(
            configuration,
            services,
            capability,
            provider,
            verification.inspection,
            error,
            &inspectionFailure)) {
        if (inspectionFailure == PamProviderInspectionFailure::Inactive) {
            std::string fileError;
            const auto fileState =
                PamProviderInspector::inspectExpectedProviderFile(
                    provider, platformConfig.moduleDirectories, fileError);
            if (fileState == PamProviderFileState::Missing) {
                verification.state = PamEnforcementState::Missing;
                verification.detail = fileError + "; " + error;
            } else if (fileState == PamProviderFileState::Untrusted) {
                verification.state = PamEnforcementState::Broken;
                verification.detail = fileError;
            } else {
                verification.state = PamEnforcementState::Inactive;
                verification.detail = error;
            }
        } else if (inspectionFailure ==
                   PamProviderInspectionFailure::Conflicting) {
            verification.state = PamEnforcementState::Conflicting;
            verification.detail = error;
        } else {
            verification.state = PamEnforcementState::Broken;
            verification.detail = error;
        }
        return false;
    }

    if (!PamProviderInspector::verifyProviderFiles(
            verification.inspection,
            platformConfig.moduleDirectories,
            error) ||
        !PamProviderInspector::verifyConfigurationFiles(
            verification.inspection,
            error)) {
        verification.state = PamEnforcementState::Broken;
        verification.detail = error;
        return false;
    }

    const auto* configuredCapability = capabilityConfig(
        platformConfig, capability);
    if (configuredCapability == nullptr ||
        configuredCapability->provider != provider ||
        (configuredCapability->configurationMode ==
             fic::platform::PamCapabilityConfigurationMode::ProviderConfigFile &&
         !PamProviderInspector::verifyExternalConfigContract(
             verification.inspection,
             *configuredCapability, error))) {
        verification.state = PamEnforcementState::Broken;
        verification.detail = configuredCapability == nullptr
            ? "PAM capability is absent from platform composition"
            : error;
        return false;
    }

    PamProviderSemanticFailure semanticFailure =
        PamProviderSemanticFailure::None;
    if (!PamProviderSemanticVerifier::verifyCapability(
            verification.inspection,
            *configuredCapability,
            mode == PamCapabilityVerificationMode::SecurityEffective,
            semanticFailure,
            error)) {
        verification.state = semanticFailure ==
                PamProviderSemanticFailure::Ineffective
            ? PamEnforcementState::Ineffective
            : PamEnforcementState::Broken;
        verification.detail = error;
        return false;
    }

    for (const auto& service : verification.inspection.services) {
        PamControlFlowAnalysis analysis;
        if (!PamControlFlowAnalyzer::analyze(
                configuration,
                platformConfig,
                service,
                capability,
                provider,
                analysis,
                error)) {
            verification.state = PamEnforcementState::Broken;
            verification.detail = error;
            return false;
        }
        if (!analysis.effective) {
            verification.violations.insert(
                verification.violations.end(),
                analysis.violations.begin(),
                analysis.violations.end());
        }
    }

    if (!verification.violations.empty()) {
        verification.state = PamEnforcementState::Ineffective;
        verification.detail = formatPamFlowViolation(
            verification.violations.front());
        return false;
    }

    verification.state = PamEnforcementState::Effective;
    verification.detail = pamProviderName(provider) +
        " is effective for all configured PAM services";
    return true;
}

std::string pamEnforcementStateName(PamEnforcementState state) {
    switch (state) {
    case PamEnforcementState::Missing:
        return "missing";
    case PamEnforcementState::Inactive:
        return "inactive";
    case PamEnforcementState::Ineffective:
        return "ineffective";
    case PamEnforcementState::Broken:
        return "broken";
    case PamEnforcementState::Conflicting:
        return "conflicting";
    case PamEnforcementState::Effective:
        return "effective";
    }
    return "unknown";
}

std::string formatPamCapabilityVerification(
    const PamCapabilityVerification& verification) {
    return "state=" + pamEnforcementStateName(verification.state) +
        ": " + verification.detail;
}

} // namespace fic::identity::pam
