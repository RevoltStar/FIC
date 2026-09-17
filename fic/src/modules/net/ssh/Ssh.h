#ifndef SSH_H
#define SSH_H

#include "modules/net/NET.h"
#include "modules/net/ssh/SshConfigFile.h"
#include "modules/net/ssh/SshRollback.h"
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
    // Deterministic test seam invoked right before the apply-time
    // compensation restore (simulates an external modification racing with
    // the compensation write).
    std::function<void()> beforeRestoreHook_;

public:
    Ssh(fic::platform::SshPlatformConfig platformConfig,
        const fic::platform::PlatformExecutableResolver& executables);
    bool apply() override;
    virtual ~Ssh();

    void setBeforeRestoreHook(std::function<void()> hook) {
        beforeRestoreHook_ = std::move(hook);
    }

    // Rollback backend options derived from the platform configuration (used
    // for in-process undo of the previous owned state on a value change).
    SshRollbackOptions makeRollbackOptions() const;

    // Managed resource identifier for the rollback system: the SSH parameter
    // FIC mutates in the shared main sshd_config.
    const std::string& managedResource() const { return sshParameter; }
};

#endif // SSH_H
