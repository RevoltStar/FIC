#ifndef NET_SSH_PORT_H
#define NET_SSH_PORT_H

#include "modules/net/submodules/Ssh.h"

class NET_ssh_port : public Ssh
{
public:
    NET_ssh_port(const fic::platform::SshPlatformConfig& platformConfig,
                 const fic::platform::SystemToolsPlatformConfig& systemTools);
    ~NET_ssh_port();
    bool apply() override;
};

#endif // NET_SSH_PORT_H
