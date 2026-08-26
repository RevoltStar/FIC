#ifndef GLOBAL_KERNEL_PROTECTION_H
#define GLOBAL_KERNEL_PROTECTION_H

#include "modules/sysctl/Sysctl.h"

//Параметры, отвечающие за ядро в целом
class GlobalKernelProtection : public Sysctl
{
public:
    GlobalKernelProtection();
    virtual ~GlobalKernelProtection() = default;
};

#endif // GLOBAL_KERNEL_PROTECTION_H
