#ifndef SYSCTL_REDIRECTS_DISABLE_H
#define SYSCTL_REDIRECTS_DISABLE_H

#include "modules/sysctl/network_kernel/NetworkKernelProtection.h"

class SYSCTL_redirects_disable : public NetworkKernelProtection
{
public:
    SYSCTL_redirects_disable();
    bool apply() override;
};

#endif // SYSCTL_REDIRECTS_DISABLE_H
