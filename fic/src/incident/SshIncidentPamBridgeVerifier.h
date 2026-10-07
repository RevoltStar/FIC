#pragma once

#include "modules/net/ssh/SshRuntime.h"
#include "platform/PlatformProfile.h"

#include <string>

namespace fic::incident {

struct SshPamBridgeReadinessResult {
    bool ready = false;
    bool optedOut = false;
    std::string diagnostic;
};

// Proves only the OpenSSH side of the bridge. The PAM account stack is
// independently verified by PamIncidentAccessGateVerifier.
class SshIncidentPamBridgeVerifier {
public:
    static bool prove(const platform::SshPlatformConfig& platform,
                      const platform::PlatformExecutableResolver& executables,
                      std::string& error,
                      SshCommandRunner runner = {});
    static SshPamBridgeReadinessResult evaluateReadiness(
        bool sshUsePamEnabled,
        const platform::SshPlatformConfig& platform,
        const platform::PlatformExecutableResolver& executables,
        SshCommandRunner runner = {});
};

} // namespace fic::incident
