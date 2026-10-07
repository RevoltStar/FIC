#pragma once

#include "incident/SshIncidentPamBridgeVerifier.h"

namespace fic::incident {

class SshIncidentPamRuntimeReconciler {
public:
    SshPamBridgeReadinessResult evaluateReadiness(
        bool sshUsePamEnabled,
        const platform::SshPlatformConfig& platform,
        const platform::PlatformExecutableResolver& executables,
        SshCommandRunner runner = {},
        SshProcessReader processReader = {});
private:
    bool reconcile(const platform::SshPlatformConfig& platform,
                          const platform::PlatformExecutableResolver& executables,
                          std::string& error,
                          SshCommandRunner runner = {},
                          SshProcessReader processReader = {});
    std::string reconciledIdentity_;
    std::uint64_t reconciledEpoch_ = 0;
};

} // namespace fic::incident
