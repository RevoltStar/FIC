#ifndef NETWORK_KERNEL_PROTECTION_H
#define NETWORK_KERNEL_PROTECTION_H

#include "modules/sysctl/Sysctl.h"

//Настройки ядра, отвечающие за сетевую защиту
class NetworkKernelProtection : public Sysctl
{
public:
    NetworkKernelProtection();
    virtual ~NetworkKernelProtection() = default;
};

#endif // NETWORK_KERNEL_PROTECTION_H
