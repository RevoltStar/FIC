#pragma once
#include "service/VerifiedConfigServiceActivator.h"
namespace fic::service::ssh {
enum class ProofState { Proven, NonCompliant, NotProven, Unsupported };
enum class SshActivationStatus { Success, Refused, ActivationFailed, RuntimeActivatedButPersistentDrift };
struct SshVerifiedActivationRequest {
    // Caller-authorized references, NEVER enrolled from observed files here.
    ActivationRequest reference;
    std::map<std::string, std::string> policies;
};
struct SshVerifiedActivationResult {
    SshActivationStatus status = SshActivationStatus::Refused;
    ProofState inputs = ProofState::NotProven;
    ProofState semantics = ProofState::NotProven;
    ProofState persistent = ProofState::NotProven;
    bool activationAttempted = false;
    ActivationResult activation;
    std::string diagnostic;
    bool success() const { return status == SshActivationStatus::Success; }
};
class SshVerifiedActivationAdapter {
public:
    static SshVerifiedActivationResult activate(const SshVerifiedActivationRequest&);
};
} // namespace fic::service::ssh
