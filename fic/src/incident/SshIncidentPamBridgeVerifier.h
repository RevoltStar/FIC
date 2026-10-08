#pragma once

#include "modules/net/ssh/SshRuntime.h"
#include "platform/PlatformProfile.h"

#include <string>
#include <vector>
#include <functional>

namespace fic::incident {

using SshMainProcessVerifier = std::function<bool(
    unsigned int, const std::filesystem::path&, std::string&)>;

struct SshPamBridgeReadinessResult {
    bool ready = false;
    bool optedOut = false;
    std::string diagnostic;
};

// ACTIVE supports only the package-declared systemd OpenSSH launch topology.
// It proves the future recipe and effective configuration; it never treats
// /proc/PID/cmdline or /proc/PID/environ as historical execve evidence.
class SshIncidentPamBridgeVerifier {
public:
    static bool proveFuture(
        const platform::SshPlatformConfig& platform,
        const platform::PlatformExecutableResolver& executables,
        std::string& error, SshCommandRunner runner = {});

    static bool proveCurrent(
        const platform::SshPlatformConfig& platform,
        const platform::PlatformExecutableResolver& executables,
        std::string& error, SshCommandRunner runner = {},
        SshMainProcessVerifier processVerifier = {});

    // After proving the future recipe, restart only already-active canonical
    // services and verify the resulting active executable and configuration.
    static bool activate(
        const platform::SshPlatformConfig& platform,
        const platform::PlatformExecutableResolver& executables,
        std::string& error, SshCommandRunner runner = {},
        SshMainProcessVerifier processVerifier = {});

    // A FIC-stopped service is started by the ownership-aware guard after
    // proving the future recipe. Re-prove the active process and unchanged
    // manager environment before declaring the bridge ready.
    static bool activateBlocked(
        const platform::SshPlatformConfig& platform,
        const platform::PlatformExecutableResolver& executables,
        std::string& error,
        const std::function<bool(std::string&)>& restoreOwned,
        SshCommandRunner runner = {},
        SshMainProcessVerifier processVerifier = {});
};

} // namespace fic::incident
