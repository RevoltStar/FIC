#ifndef SSH_H
#define SSH_H

#include "modules/net/NET.h"
#include "modules/net/submodules/SshConfigFile.h"
#include "platform/PlatformProfile.h"

#include <filesystem>
#include <memory>
#include <string>

struct SshRuntimeOptions;

class Ssh : public Net
{
protected:
    fic::platform::SshPlatformConfig platformConfig_;
    std::unique_ptr<SshRuntimeOptions> runtimeOptions_;
    std::unique_ptr<SshConfigFileHandler> sshConfig_;
    std::string sshParameter;

public:
    Ssh(fic::platform::SshPlatformConfig platformConfig,
        const fic::platform::SystemToolsPlatformConfig& systemTools);
    bool apply() override;
    virtual ~Ssh();
};

#endif // SSH_H
