#pragma once

#include "incident/SshIncidentPamBridgeVerifier.h"

#include <functional>
#include <string>

namespace fic::incident {

struct AccessReadinessResult {
    bool ready = false;
    bool sshOptedOut = false;
    std::string diagnostic;
};

// Both proofs are evaluated from the current state on every recomputation.
// The SSH opt-out does not weaken the permanent PAM gate requirement.
class AccessReadinessVerifier {
public:
    using PamProof = std::function<bool(std::string&)>;
    using SshProof = std::function<SshPamBridgeReadinessResult()>;

    static AccessReadinessResult evaluate(const PamProof& pamProof,
                                          const SshProof& sshProof) {
        std::string error;
        if (!pamProof(error)) {
            return {false, false,
                    "incident PAM access gate topology is not proven: " + error};
        }
        const auto ssh = sshProof();
        return {ssh.ready, ssh.optedOut, ssh.diagnostic};
    }
};

} // namespace fic::incident
