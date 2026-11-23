#pragma once
#include "service/VerifiedConfigServiceActivator.h"
#include "service/ssh/SshVerifiedInputClosure.h"
#include "platform/PlatformProfile.h"
#include <memory>
#include <fic/core/fs/AtomicFileWriter.h>
namespace fic::service::detail {struct SshUnitReferences;}
namespace fic::identity::pam {struct PamSshMfaCandidate;}
namespace fic::service::ssh {
enum class ProofState { Proven, NonCompliant, NotProven, Unsupported };
enum class SshActivationStatus { Success, Refused, ActivationFailed, RuntimeActivatedButPersistentDrift, ReleasedOffline };
struct SshReleaseAdmission {
    bool offline=false;
    std::map<std::string,std::string> service;
    std::shared_ptr<const fic::service::detail::SshUnitReferences> unitReferences;
};
struct SshConfigurationValidationResult {
    bool validated=false;
    ActivationResult snapshot;
    std::string diagnostic;
    bool success() const {return validated&&snapshot.success()&&!snapshot.readinessConfirmed;}
};
struct SshVerifiedActivationRequest {
    // Caller-authorized references, NEVER enrolled from observed files here.
    ActivationRequest reference;
    std::map<std::string, std::string> policies;
    // Operation-local expectations from the production caller. No journal or
    // ownership authority is inferred from these read-only observations.
    std::map<std::string,std::string> expectedService;
    // Optional authoritative enabled policy values. Only independently proven
    // compliant selections enter the receipt; they never gate this apply.
    std::map<std::string,std::string> additionalPolicies;
    std::map<std::string,std::string> observedMetadata;
    SshActivationIntent intent=SshActivationIntent::SelectedPolicies;
    // Only multi-file Port release may restore a bounded, duplicate-free set.
    // SelectedPolicies and other policy callers keep the single-port contract.
    bool allowReleasedPortSet=false;
    struct MfaRequirement {
        bool sssd=false;
        std::optional<fic::platform::PamFaillockStrategy> faillock;
        bool operator==(const MfaRequirement& other) const {
            return sssd == other.sssd && faillock == other.faillock;
        }
        bool operator!=(const MfaRequirement& other) const { return !(*this == other); }
    };
    // Explicit caller authority. PAM paths and expected digests belong to the
    // same reference snapshot as SSH files and are never inferred from markers.
    std::optional<MfaRequirement> mfa;
};
struct SshMfaReference {
    SshVerifiedActivationRequest::MfaRequirement requirement;
    std::vector<ControlledPath> pamInputs;
};
struct SshVerifiedActivationResult {
    SshActivationStatus status = SshActivationStatus::Refused;
    ProofState inputs = ProofState::NotProven;
    ProofState semantics = ProofState::NotProven;
    ProofState persistent = ProofState::NotProven;
    bool activationAttempted = false;
    ActivationResult activation;
    // Observed identity/facts from the same verified operation, not ownership.
    std::map<std::string,std::string> runtimeEvidence;
    std::string diagnostic;
    bool success() const { return status == SshActivationStatus::Success||status==SshActivationStatus::ReleasedOffline; }
    std::map<std::string,std::string> observedFacts() const;
};
struct SshPortSourceMap {
    SshVerifiedActivationRequest reference;
    detail::Closure graph;
    std::map<std::string,AtomicTargetState> files;
};
class SshVerifiedActivationAdapter {
public:
    static std::map<std::string,std::string> serviceAdmission();
    static SshReleaseAdmission releaseAdmission(const SshVerifiedActivationRequest&);
    // Bind metadata to already authorized byte references for a Debian 13
    // MFA transition. No source is discovered or enrolled by this method.
    static SshReleaseAdmission admitMfaPlan(SshVerifiedActivationRequest&);
    // Read-only platform input capture. Caller MUST first prove journal/managed
    // ownership and supply the expected main-file digest. Foreign root-owned
    // configuration is referenced, never enrolled as policy ownership.
    static SshVerifiedActivationRequest captureReference(
        const std::map<std::string,std::string>& policies,const std::string& expectedMainSha,
        SshActivationIntent intent=SshActivationIntent::SelectedPolicies,
        const SshMfaReference* mfa=nullptr);
    // Planning only: no selected-policy semantics/runtime proof or mutation.
    // Uses the same closed input graph and trust checks as release capture.
    static SshPortSourceMap capturePortSources(const std::string& expectedMainSha,
        const std::set<std::string>& previouslyOwnedFiles={},const SshMfaReference* mfa=nullptr);
    static void validatePortPlan(const SshPortSourceMap&,const std::map<std::string,std::string>& targets,
        const std::map<std::string,std::string>& policies,SshActivationIntent);
    static bool sameAuthorizedPortGeneration(const SshVerifiedActivationRequest& before,
        const SshVerifiedActivationRequest& after,const std::map<std::string,AtomicTargetState>& installed);
    static void prepareRuntimeProbe(const SshVerifiedActivationRequest&);
    static SshVerifiedActivationResult activate(const SshVerifiedActivationRequest&);
    static SshConfigurationValidationResult validateReleasePlan(
        const SshVerifiedActivationRequest&,const SshReleaseAdmission&,const std::string& plannedMain);
    static SshConfigurationValidationResult validateMfaPlan(
        const SshVerifiedActivationRequest&, const SshReleaseAdmission&, const std::string& plannedMain,
        std::optional<SshVerifiedActivationRequest::MfaRequirement> proposed,
        const fic::identity::pam::PamSshMfaCandidate* candidate = nullptr);
    static SshVerifiedActivationResult releaseConfiguration(
        const SshVerifiedActivationRequest&,const SshReleaseAdmission&);
    static bool sameInputGeneration(const SshVerifiedActivationRequest& before,
        const SshVerifiedActivationRequest& after,bool mainMayDiffer);
};
} // namespace fic::service::ssh
