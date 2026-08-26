#ifndef SYSCTL_SEND_REDIRECTS_DISABLE_H
#define SYSCTL_SEND_REDIRECTS_DISABLE_H

#include "modules/sysctl/network_kernel/NetworkKernelProtection.h"


class SYSCTL_send_redirects_disable : public NetworkKernelProtection
{
public:
    SYSCTL_send_redirects_disable();
    bool apply() override;
};

#endif // SYSCTL_SEND_REDIRECTS_DISABLE_H
