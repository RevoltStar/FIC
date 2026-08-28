#ifndef FIC_IDENTITY_ACCESS_PAM_CAPABILITY_VERIFIER_H
#define FIC_IDENTITY_ACCESS_PAM_CAPABILITY_VERIFIER_H

#include "modules/identity_access/pam/PamControlFlowAnalyzer.h"

#include <string>
#include <vector>

namespace fic::identity::pam {

enum class PamEnforcementState {
    Missing,
    Inactive,
    Ineffective,
    Broken,
    Conflicting,
    Effective
};

enum class PamCapabilityVerificationMode {
    Structural,
    SecurityEffective
};

struct PamCapabilityVerification {
    PamEnforcementState state = PamEnforcementState::Broken;
    PamProviderInspection inspection;
    std::vector<PamFlowViolation> violations;
    std::string detail;
};

class PamCapabilityVerifier {
public:
    static bool verify(
        PamConfiguration& configuration,
        const fic::platform::PamPlatformConfig& platformConfig,
        const std::vector<std::string>& services,
        PamCapability capability,
        PamProviderKind provider,
        PamCapabilityVerification& verification,
        PamCapabilityVerificationMode mode =
            PamCapabilityVerificationMode::SecurityEffective);
};

std::string pamEnforcementStateName(PamEnforcementState state);
std::string formatPamCapabilityVerification(
    const PamCapabilityVerification& verification);

} // namespace fic::identity::pam

#endif // FIC_IDENTITY_ACCESS_PAM_CAPABILITY_VERIFIER_H
