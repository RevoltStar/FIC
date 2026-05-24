#ifndef SYSCTL_BUFFER_OVERFLOW_PROTECTION_H
#define SYSCTL_BUFFER_OVERFLOW_PROTECTION_H

#include "modules/sysctl/submodules/GlobalKernelProtection.h"

//Защита от переполнения буфера
class SYSCTL_buffer_overflow_protection : public GlobalKernelProtection
{
public:
    SYSCTL_buffer_overflow_protection();
    bool check_and_fix() override;
};


#endif // SYSCTL_BUFFER_OVERFLOW_PROTECTION_H
