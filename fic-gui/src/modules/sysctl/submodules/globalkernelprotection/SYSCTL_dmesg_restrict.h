#ifndef SYSCTL_DMESG_RESTRICT_H
#define SYSCTL_DMESG_RESTRICT_H

#include "modules/sysctl/submodules/GlobalKernelProtection.h"

class SYSCTL_dmesg_restrict : public GlobalKernelProtection
{
public:
    SYSCTL_dmesg_restrict();
    bool check_and_fix() override;
};

#endif // SYSCTL_DMESG_RESTRICT_H
