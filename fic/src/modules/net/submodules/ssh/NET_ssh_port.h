#ifndef NET_SSH_PORT_H
#define NET_SSH_PORT_H

#include "modules/net/submodules/Ssh.h"

class NET_ssh_port : public Ssh
{
public:
    NET_ssh_port();
    ~NET_ssh_port();
    bool check_and_fix() override;
};

#endif // NET_SSH_PORT_H
