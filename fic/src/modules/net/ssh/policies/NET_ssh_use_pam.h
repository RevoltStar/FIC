#ifndef NET_SSH_USE_PAM_H
#define NET_SSH_USE_PAM_H

#include "modules/net/ssh/Ssh.h"

class NET_ssh_use_pam : public Ssh {
public:
    NET_ssh_use_pam(
        const fic::platform::SshPlatformConfig& platformConfig,
        const fic::platform::PlatformExecutableResolver& executables);
    bool apply() override;
};

#endif
