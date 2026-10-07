#pragma once

#include "modules/net/ssh/SshRuntime.h"
#include "platform/PlatformProfile.h"

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace fic::incident {

struct SshLaunchProof {
    std::string serviceUnit;
    std::string argvZero;
    std::vector<std::string> configurationArguments;
    std::filesystem::path configPath;
    bool activeProcess = false;
};

struct SshProcessSnapshot {
    std::uint64_t device = 0;
    std::uint64_t inode = 0;
    std::string startTime;
    std::vector<std::string> arguments;
};

enum class SshActivationStatus { Proven, Unproven };

struct SshActivationProof {
    SshActivationStatus status = SshActivationStatus::Unproven;
    std::uint64_t trustedDevice = 0;
    std::uint64_t trustedInode = 0;
    std::vector<SshLaunchProof> launches;
    std::string diagnostic;
};

using SshProcessReader = std::function<bool(
    unsigned int, SshProcessSnapshot&, std::string&)>;

class SshSystemdActivationVerifier {
public:
    static SshActivationProof prove(
        const platform::SshPlatformConfig& platform,
        const platform::PlatformExecutableResolver& executables,
        SshCommandRunner runner = {},
        SshProcessReader processReader = {});
};

} // namespace fic::incident
