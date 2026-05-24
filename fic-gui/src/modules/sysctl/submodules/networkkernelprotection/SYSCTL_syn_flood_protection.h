#ifndef SYSCTL_SYN_FLOOD_PROTECTION_H
#define SYSCTL_SYN_FLOOD_PROTECTION_H

#include "modules/sysctl/submodules/NetworkKernelProtection.h"

class SYSCTL_syn_flood_protection : public NetworkKernelProtection
{
public:
    SYSCTL_syn_flood_protection();
    bool check_and_fix() override;
};
#endif // SYSCTL_SYN_FLOOD_PROTECTION_H
