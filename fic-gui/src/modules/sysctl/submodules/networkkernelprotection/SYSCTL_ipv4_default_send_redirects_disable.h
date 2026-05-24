#ifndef SYSCTL_IPV4_DEFAULT_SEND_REDIRECTS_DISABLE_H
#define SYSCTL_IPV4_DEFAULT_SEND_REDIRECTS_DISABLE_H

#include "modules/sysctl/submodules/NetworkKernelProtection.h"

class SYSCTL_ipv4_default_send_redirects_disable : public NetworkKernelProtection
{
public:
    SYSCTL_ipv4_default_send_redirects_disable();
    bool check_and_fix() override;
};

#endif // SYSCTL_IPV4_DEFAULT_SEND_REDIRECTS_DISABLE_H
