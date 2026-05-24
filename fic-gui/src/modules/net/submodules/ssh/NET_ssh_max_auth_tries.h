#ifndef NET_SSH_MAX_AUTH_TRIES_H
#define NET_SSH_MAX_AUTH_TRIES_H

#include "modules/net/submodules/Ssh.h"

class NET_ssh_max_auth_tries : public Ssh
{
public:
    NET_ssh_max_auth_tries();
    ~NET_ssh_max_auth_tries();
    bool check_and_fix() override;
};

#endif // NET_SSH_MAX_AUTH_TRIES_H
