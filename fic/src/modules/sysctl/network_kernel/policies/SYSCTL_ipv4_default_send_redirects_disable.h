#ifndef SYSCTL_IPV4_DEFAULT_SEND_REDIRECTS_DISABLE_H
#define SYSCTL_IPV4_DEFAULT_SEND_REDIRECTS_DISABLE_H

#include "modules/sysctl/network_kernel/NetworkKernelProtection.h"

class SYSCTL_ipv4_default_send_redirects_disable : public NetworkKernelProtection
{
public:
    SYSCTL_ipv4_default_send_redirects_disable();
    bool apply() override;
};

#endif // SYSCTL_IPV4_DEFAULT_SEND_REDIRECTS_DISABLE_H
