#pragma once

#include "incident/SshIncidentPamBridgeVerifier.h"

namespace fic::incident {

class SshIncidentPamRuntimeReconciler {
public:
    static SshPamBridgeReadinessResult evaluateReadiness(
        bool sshUsePamEnabled,
        const platform::SshPlatformConfig& platform,
        const platform::PlatformExecutableResolver& executables,
        SshCommandRunner runner = {},
        SshProcessReader processReader = {});
    static bool reconcile(const platform::SshPlatformConfig& platform,
                          const platform::PlatformExecutableResolver& executables,
                          std::string& error,
                          SshCommandRunner runner = {},
                          SshProcessReader processReader = {});
};

} // namespace fic::incident
