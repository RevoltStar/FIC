#pragma once
#include "service/VerifiedConfigServiceActivator.h"
#include "service/ssh/SshVerifiedInputClosure.h"
#include <memory>
namespace fic::service::detail {struct SshUnitReferences;}
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
class SshVerifiedActivationAdapter {
public:
    static std::map<std::string,std::string> serviceAdmission();
    static SshReleaseAdmission releaseAdmission(const SshVerifiedActivationRequest&);
    // Read-only platform input capture. Caller MUST first prove journal/managed
    // ownership and supply the expected main-file digest. Foreign root-owned
    // configuration is referenced, never enrolled as policy ownership.
    static SshVerifiedActivationRequest captureReference(
        const std::map<std::string,std::string>& policies,const std::string& expectedMainSha,
        SshActivationIntent intent=SshActivationIntent::SelectedPolicies);
    static void prepareRuntimeProbe(const SshVerifiedActivationRequest&);
    static SshVerifiedActivationResult activate(const SshVerifiedActivationRequest&);
    static SshConfigurationValidationResult validateReleasePlan(
        const SshVerifiedActivationRequest&,const SshReleaseAdmission&,const std::string& plannedMain);
    static SshVerifiedActivationResult releaseConfiguration(
        const SshVerifiedActivationRequest&,const SshReleaseAdmission&);
    static bool sameInputGeneration(const SshVerifiedActivationRequest& before,
        const SshVerifiedActivationRequest& after,bool mainMayDiffer);
};
} // namespace fic::service::ssh
