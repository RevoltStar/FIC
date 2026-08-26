#ifndef SYSCTL_DMESG_RESTRICT_H
#define SYSCTL_DMESG_RESTRICT_H

#include "modules/sysctl/global_kernel/GlobalKernelProtection.h"

class SYSCTL_dmesg_restrict : public GlobalKernelProtection
{
public:
    SYSCTL_dmesg_restrict();
    bool apply() override;
};

#endif // SYSCTL_DMESG_RESTRICT_H
