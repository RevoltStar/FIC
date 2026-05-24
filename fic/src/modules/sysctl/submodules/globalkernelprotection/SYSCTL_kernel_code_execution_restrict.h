#ifndef SYSCTL_KERNEL_CODE_EXECUTION_RESTRICT_H
#define SYSCTL_KERNEL_CODE_EXECUTION_RESTRICT_H


#include "modules/sysctl/submodules/GlobalKernelProtection.h"
//Запрет исполнения кода в стеке и куче
class SYSCTL_kernel_code_execution_restrict : public GlobalKernelProtection
{
public:
    SYSCTL_kernel_code_execution_restrict();
    bool check_and_fix() override;
};


#endif // SYSCTL_KERNEL_CODE_EXECUTION_RESTRICT_H
