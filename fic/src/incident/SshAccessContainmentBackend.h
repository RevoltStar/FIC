#pragma once

#include "modules/net/ssh/SshRuntime.h"
#include "platform/PlatformProfile.h"

#include <fic/core/fs/AtomicFileWriter.h>

#include <filesystem>
#include <map>
#include <optional>
#include <string>

namespace fic::incident {

class SshAccessContainmentBackend {
public:
    struct WitnessOptions {
        std::filesystem::path path;
        std::string bootId;
        uid_t owner = 0;
        gid_t group = 0;
        mode_t parentMode = 0755;
    };

    SshAccessContainmentBackend();
    explicit SshAccessContainmentBackend(WitnessOptions options);
    bool load(const platform::SshPlatformConfig& platform, std::string& error);
    bool block(const platform::SshPlatformConfig& platform,
               const platform::PlatformExecutableResolver& executables,
               std::string& error, SshCommandRunner runner = {});
    bool restore(const platform::SshPlatformConfig& platform,
                 const platform::PlatformExecutableResolver& executables,
                 std::string& error, SshCommandRunner runner = {});
    bool ownsBlock() const { return !services_.empty() || !sockets_.empty(); }

private:
    enum class StopState { Intent, Stopped };
    using StopMap = std::map<std::string, StopState>;
    bool save(std::string& error);
    WitnessOptions options_;
    StopMap services_;
    StopMap sockets_;
    std::optional<AtomicTargetState> witnessState_;
};

} // namespace fic::incident
