#include "modules/identity_access/submodules/pam/PamCapabilityVerifier.h"

namespace fic::identity::pam {

bool PamCapabilityVerifier::verify(
    PamConfiguration& configuration,
    const fic::platform::PamPlatformConfig& platformConfig,
    const std::vector<std::string>& services,
    PamCapability capability,
    PamProviderKind provider,
    PamCapabilityVerification& verification) {
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
