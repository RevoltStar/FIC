#ifndef FIC_IDENTITY_ACCESS_PAM_CONTROL_FLOW_ANALYZER_H
#define FIC_IDENTITY_ACCESS_PAM_CONTROL_FLOW_ANALYZER_H

#include "modules/identity_access/pam/PamConfiguration.h"
#include "modules/identity_access/pam/PamProviderInspector.h"

#include <optional>
#include <string>
#include <vector>

namespace fic::identity::pam {

enum class PamFlowViolationKind {
    ProviderUnreachable,
    AuthenticationBypass,
    PasswordEnforcementBypass,
    FailureAccountingBypass,
    RecoverableFailureAccounting,
    SuccessAccountingBypass,
    PrematureSuccessAccounting,
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

struct PamTrustedAuthenticationExclusionAcceptance {
    std::string service;
    std::string module;
    fic::platform::PamTrustedAuthenticationExclusionReason reason =
        fic::platform::PamTrustedAuthenticationExclusionReason::
            ExplicitSubjectExclusion;
    std::string excludedUser;
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
    std::vector<PamTrustedAuthenticationExclusionAcceptance>
        acceptedTrustedAuthenticationExclusions;
};

// Password-specific control-flow analysis (Rule G security proof). All
// answers come from symbolic execution of the real Linux-PAM control flow
// over the parsed effective stack — never from textual index ordering.
struct PamPasswordFlowAnalysis {
    // No successful password-change path skips pam_pwquality.so.
    bool qualityNonBypassable = false;
    // No successful password-change path reaches the stack completion
    // without pam_pwhistory.so use_authtok enforcement on that path.
    bool historyNonBypassable = false;
    // No successful path reaches pam_pwhistory.so without a proven token
    // producer success (pam_pwquality.so) earlier on the SAME path
    // (token-state symbolic execution).
    bool historyAlwaysHasTokenProducer = false;
    // Unsupported/unrepresentable control flow (unknown control syntax,
    // unsupported jump, cycle, budget exhaustion, unsafe substack
    // semantics, unknown significant result) — every entry fails closed.
    std::vector<PamFlowViolation> violations;
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

// Classifies the pam_faillock topology of an expanded authentication stack
// into one of the supported integration strategies. Returns nullopt and sets
// error when the topology is not enabled, is ambiguous, or cannot be proven
// to match exactly one strategy (fail closed).
std::optional<fic::platform::PamFaillockStrategy> detectPamFaillockStrategy(
    const PamEffectiveStack& authStack,
    std::string& error);

std::string pamFlowViolationKindName(PamFlowViolationKind kind);
std::string formatPamFlowViolation(const PamFlowViolation& violation);

// Password-flow security proof for Rule G: symbolically executes the
// effective Primary password stack (the same interpreter semantics the
// analyzer uses for other groups) and classifies quality/history
// non-bypassability plus the token-producer invariant. The stack is
// analyzed as a graph (substacks are executed in their own scope; jumps
// are honored as Linux-PAM honors them); textual positions are never used
// as a proof. Returns false only when the analysis could not be performed
// at all; unsupported control flow is reported through analysis.violations
// (fail closed).
bool analyzePasswordFlow(const PamEffectiveStack& stack,
                         const fic::platform::PamPlatformConfig& platformConfig,
                         PamPasswordFlowAnalysis& analysis,
                         std::string& error);

} // namespace fic::identity::pam

#endif // FIC_IDENTITY_ACCESS_PAM_CONTROL_FLOW_ANALYZER_H
