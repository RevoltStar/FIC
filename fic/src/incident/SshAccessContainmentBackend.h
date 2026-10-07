#pragma once

#include "modules/net/ssh/SshRuntime.h"
#include "platform/PlatformProfile.h"

#include <set>
#include <string>

namespace fic::incident {

class SshAccessContainmentBackend {
public:
    bool block(const platform::SshPlatformConfig& platform,
               const platform::PlatformExecutableResolver& executables,
               std::string& error, SshCommandRunner runner = {});
    bool restore(const platform::SshPlatformConfig& platform,
                 const platform::PlatformExecutableResolver& executables,
                 std::string& error, SshCommandRunner runner = {});
    bool ownsBlock() const { return !stoppedServices_.empty() ||
                                    !stoppedSockets_.empty(); }

private:
    std::set<std::string> stoppedServices_;
    std::set<std::string> stoppedSockets_;
};

} // namespace fic::incident
