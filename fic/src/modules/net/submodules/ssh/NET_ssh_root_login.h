#ifndef NET_SSH_ROOT_LOGIN_H
#define NET_SSH_ROOT_LOGIN_H

#include "modules/net/submodules/Ssh.h"

class NET_ssh_root_login : public Ssh
{
public:
    NET_ssh_root_login();
    ~NET_ssh_root_login();
    bool check_and_fix() override;
};

#endif // NET_SSH_ROOT_LOGIN_H
