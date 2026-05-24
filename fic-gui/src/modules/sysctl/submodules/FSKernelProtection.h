#ifndef FS_KERNEL_PROTECTION_H
#define FS_KERNEL_PROTECTION_H

#include "modules/sysctl/Sysctl.h"

//Настройки ядра, отвечающие за защиту ФС
class FSKernelProtection : public Sysctl
{
public:
    FSKernelProtection();
    virtual ~FSKernelProtection() = default;
};


#endif // FS_KERNEL_PROTECTION_H
