#include "modules/sysctl/submodules/globalkernelprotection/SYSCTL_kernel_code_execution_restrict.h"

SYSCTL_kernel_code_execution_restrict::SYSCTL_kernel_code_execution_restrict()
    : GlobalKernelProtection()
{
    this->Sysctl::sysctlParameter = "kernel.kptr_restrict";
    this->Sysctl::sysctlParameterValue = "2";
    this->policyName = "kernel_kptr_restrict";
    this->policyTypeValue = std::make_unique<PossibleListPolicyTypeValue>(
        std::vector<std::string>{"2", "0", "1"});
}

bool SYSCTL_kernel_code_execution_restrict::check_and_fix()
{
    return this->Sysctl::check_and_fix();
}
