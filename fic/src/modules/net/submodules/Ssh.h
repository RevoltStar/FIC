#ifndef SSH_H
#define SSH_H

#include "modules/net/NET.h"
#include "modules/net/submodules/SshConfigFile.h"

#include <memory>
#include <string>

class Ssh : public Net
{
protected:
    const static std::string sshPath;
    static std::unique_ptr<SshConfigFileHandler> sshConfig;
    std::string sshParameter;

public:
    Ssh();
    bool apply() override;
    virtual ~Ssh();
};

#endif // SSH_H
