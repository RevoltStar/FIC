#ifndef SYSCTL_PTRACE_RESTRICT_H
#define SYSCTL_PTRACE_RESTRICT_H

#include "modules/sysctl/submodules/GlobalKernelProtection.h"

//Запрет (ограничение) трассировки с помощью ptrace
class SYSCTL_ptrace_restrict : public GlobalKernelProtection
{
public:
    SYSCTL_ptrace_restrict();
    bool check_and_fix() override;
};

#endif // SYSCTL_PTRACE_RESTRICT_H
