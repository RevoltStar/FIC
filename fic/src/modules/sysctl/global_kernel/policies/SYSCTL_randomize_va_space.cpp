#include "modules/sysctl/global_kernel/policies/SYSCTL_randomize_va_space.h"

SYSCTL_randomize_va_space::SYSCTL_randomize_va_space()
    : GlobalKernelProtection()
{
    this->Sysctl::sysctlParameter = "kernel.randomize_va_space";
    this->Sysctl::sysctlParameterValue = "2";
    this->policyName = "kernel_randomize_va_space";
    this->policyTypeValue = std::make_unique<PossibleListPolicyTypeValue>(
        std::vector<std::string>{"2", "0", "1"});
}

bool SYSCTL_randomize_va_space::apply()
{
    return this->Sysctl::apply();
}
