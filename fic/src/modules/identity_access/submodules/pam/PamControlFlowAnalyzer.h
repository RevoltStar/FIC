#ifndef FIC_IDENTITY_ACCESS_PAM_CONTROL_FLOW_ANALYZER_H
#define FIC_IDENTITY_ACCESS_PAM_CONTROL_FLOW_ANALYZER_H

#include "modules/identity_access/submodules/pam/PamConfiguration.h"
#include "modules/identity_access/submodules/pam/PamProviderInspector.h"

#include <string>
#include <vector>

namespace fic::identity::pam {

enum class PamFlowViolationKind {
    ProviderUnreachable,
    AuthenticationBypass,
    PasswordEnforcementBypass,
    FailureAccountingBypass,
    SuccessAccountingBypass,
    UnsupportedControlFlow
};

struct PamFlowStep {
    std::filesystem::path source;
    std::size_t line = 0;
    std::string module;
    std::string result;
    std::string control;
    std::string action;
};

struct PamFlowViolation {
    PamFlowViolationKind kind = PamFlowViolationKind::UnsupportedControlFlow;
    std::string service;
    PamManagementGroup group = PamManagementGroup::Auth;
    std::string message;
    std::vector<PamFlowStep> path;
    bool pathTruncated = false;
};

struct PamTrustedAuthenticationBypassAcceptance {
    std::string service;
    std::string module;
    fic::platform::PamTrustedAuthenticationBypassReason reason =
        fic::platform::PamTrustedAuthenticationBypassReason::
            AlreadyPrivilegedCaller;
    std::filesystem::path source;
    std::size_t line = 0;
    std::vector<PamFlowStep> path;
    bool pathTruncated = false;
};

struct PamControlFlowAnalysis {
    bool effective = false;
    std::vector<PamFlowViolation> violations;
    std::vector<PamTrustedAuthenticationBypassAcceptance>
        acceptedTrustedAuthenticationBypasses;
};

class PamControlFlowAnalyzer {
public:
    // false means that the effective graph or control syntax could not be
    // represented safely. A successful call can still report ineffective.
    static bool analyze(PamConfiguration& configuration,
                        const fic::platform::PamPlatformConfig& platformConfig,
                        const std::string& service,
                        PamCapability capability,
                        PamProviderKind provider,
                        PamControlFlowAnalysis& analysis,
                        std::string& error);
};

std::string pamFlowViolationKindName(PamFlowViolationKind kind);
std::string formatPamFlowViolation(const PamFlowViolation& violation);

} // namespace fic::identity::pam

#endif // FIC_IDENTITY_ACCESS_PAM_CONTROL_FLOW_ANALYZER_H
