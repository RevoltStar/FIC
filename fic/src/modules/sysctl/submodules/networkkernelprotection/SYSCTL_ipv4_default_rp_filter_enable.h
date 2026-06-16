#ifndef SYSCTL_IPV4_DEFAULT_RP_FILTER_ENABLE_H
#define SYSCTL_IPV4_DEFAULT_RP_FILTER_ENABLE_H

#include "modules/sysctl/submodules/NetworkKernelProtection.h"

class SYSCTL_ipv4_default_rp_filter_enable : public NetworkKernelProtection
{
public:
    SYSCTL_ipv4_default_rp_filter_enable();
    bool apply() override;
};

#endif // SYSCTL_IPV4_DEFAULT_RP_FILTER_ENABLE_H
