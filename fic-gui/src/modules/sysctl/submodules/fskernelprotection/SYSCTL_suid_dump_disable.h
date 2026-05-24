#ifndef SYSCTL_SUID_DUMP_DISABLE_H
#define SYSCTL_SUID_DUMP_DISABLE_H

#include "modules/sysctl/submodules/FSKernelProtection.h"

class SYSCTL_suid_dump_disable : public FSKernelProtection
{
public:
    SYSCTL_suid_dump_disable();
    bool check_and_fix() override;
};

#endif // SYSCTL_SUID_DUMP_DISABLE_H
