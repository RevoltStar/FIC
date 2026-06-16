#ifndef SYSCTL_RP_FILTER_ENABLE_H
#define SYSCTL_RP_FILTER_ENABLE_H
#include "modules/sysctl/submodules/NetworkKernelProtection.h"

class SYSCTL_rp_filter_enable : public NetworkKernelProtection
{
public:
    SYSCTL_rp_filter_enable();
    bool apply() override;
};
#endif // SYSCTL_RP_FILTER_ENABLE_H
