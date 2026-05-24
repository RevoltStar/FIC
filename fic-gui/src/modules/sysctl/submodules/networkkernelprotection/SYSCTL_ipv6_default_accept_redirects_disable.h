#ifndef SYSCTL_IPV6_DEFAULT_ACCEPT_REDIRECTS_DISABLE_H
#define SYSCTL_IPV6_DEFAULT_ACCEPT_REDIRECTS_DISABLE_H

#include "modules/sysctl/submodules/NetworkKernelProtection.h"

class SYSCTL_ipv6_default_accept_redirects_disable : public NetworkKernelProtection
{
public:
    SYSCTL_ipv6_default_accept_redirects_disable();
    bool check_and_fix() override;
};

#endif // SYSCTL_IPV6_DEFAULT_ACCEPT_REDIRECTS_DISABLE_H
