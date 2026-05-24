#ifndef NET_SSH_PUBKEY_AUTH_H
#define NET_SSH_PUBKEY_AUTH_H

#include "modules/net/submodules/Ssh.h"

class NET_ssh_pubkey_auth : public Ssh
{
public:
    NET_ssh_pubkey_auth();
    ~NET_ssh_pubkey_auth();
    bool check_and_fix() override;
};

#endif // NET_SSH_PUBKEY_AUTH_H
