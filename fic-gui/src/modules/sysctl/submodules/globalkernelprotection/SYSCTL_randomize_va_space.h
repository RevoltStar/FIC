#ifndef SYSCTL_RANDOMIZE_VA_SPACE_H
#define SYSCTL_RANDOMIZE_VA_SPACE_H

#include "modules/sysctl/submodules/GlobalKernelProtection.h"

class SYSCTL_randomize_va_space : public GlobalKernelProtection
{
public:
    SYSCTL_randomize_va_space();
    bool check_and_fix() override;
};

#endif // SYSCTL_RANDOMIZE_VA_SPACE_H
