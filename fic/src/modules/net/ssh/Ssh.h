#ifndef SSH_H
#define SSH_H

#include "modules/net/NET.h"
#include "modules/net/ssh/SshConfigFile.h"
#include "modules/net/ssh/SshRuntime.h"
#include "platform/PlatformExecutableResolver.h"
#include "platform/PlatformProfile.h"

#include <filesystem>
#include <functional>
#include <memory>
#include <string>

class Ssh : public Net
{
protected:
    fic::platform::SshPlatformConfig platformConfig_;
    const fic::platform::PlatformExecutableResolver& executables_;
    std::unique_ptr<SshRuntimeOptions> runtimeOptions_;
    std::unique_ptr<SshConfigFileHandler> sshConfig_;
    std::string sshParameter;
    // Command runner hook for tests; an empty runner falls back to the
    // VerifiedProcessExecutor.
    SshCommandRunner commandRunner_;
    // Deterministic test seam invoked right before the conditional atomic
    // write of the apply path (simulates concurrent external modification).
    std::function<void()> beforeWriteHook_;

public:
    Ssh(fic::platform::SshPlatformConfig platformConfig,
        const fic::platform::PlatformExecutableResolver& executables);
    bool apply() override;
    virtual ~Ssh();

    // Managed resource identifier for the rollback system: the SSH parameter
    // FIC mutates in the shared main sshd_config.
    const std::string& managedResource() const { return sshParameter; }
};

#endif // SSH_H
