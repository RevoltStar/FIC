#ifndef NET_SSH_PUBKEY_AUTH_H
#define NET_SSH_PUBKEY_AUTH_H

#include "modules/net/ssh/Ssh.h"

class NET_ssh_pubkey_auth : public Ssh
{
public:
    explicit NET_ssh_pubkey_auth(
        const fic::platform::SshPlatformConfig& platformConfig,
        const fic::platform::PlatformExecutableResolver& executables);
    ~NET_ssh_pubkey_auth();
    bool apply() override;
};

#endif // NET_SSH_PUBKEY_AUTH_H
