#ifndef SYSCTL_SYSRQ_DISABLE_H
#define SYSCTL_SYSRQ_DISABLE_H

#include "modules/sysctl/global_kernel/GlobalKernelProtection.h"

class SYSCTL_sysrq_disable : public GlobalKernelProtection
{
public:
    SYSCTL_sysrq_disable();
    bool apply() override;
};

#endif // SYSCTL_SYSRQ_DISABLE_H
