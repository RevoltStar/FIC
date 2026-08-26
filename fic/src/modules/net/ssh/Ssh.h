#ifndef SSH_H
#define SSH_H

#include "modules/net/NET.h"
#include "modules/net/ssh/SshConfigFile.h"
#include "platform/PlatformExecutableResolver.h"
#include "platform/PlatformProfile.h"

#include <filesystem>
#include <memory>
#include <string>

struct SshRuntimeOptions;

class Ssh : public Net
{
protected:
    fic::platform::SshPlatformConfig platformConfig_;
    const fic::platform::PlatformExecutableResolver& executables_;
    std::unique_ptr<SshRuntimeOptions> runtimeOptions_;
    std::unique_ptr<SshConfigFileHandler> sshConfig_;
    std::string sshParameter;

public:
    Ssh(fic::platform::SshPlatformConfig platformConfig,
        const fic::platform::PlatformExecutableResolver& executables);
    bool apply() override;
    virtual ~Ssh();
};

#endif // SSH_H
