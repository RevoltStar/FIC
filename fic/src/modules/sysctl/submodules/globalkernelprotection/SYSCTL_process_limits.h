#ifndef SYSCTL_PROCESS_LIMITS_H
#define SYSCTL_PROCESS_LIMITS_H

#include "modules/sysctl/submodules/GlobalKernelProtection.h"

//Ограничение количества пользовательских процессов
class SYSCTL_process_limits : public GlobalKernelProtection
{
public:
    SYSCTL_process_limits();
    bool apply() override;
};

#endif // SYSCTL_PROCESS_LIMITS_H
