#include "modules/sysctl/submodules/globalkernelprotection/SYSCTL_dmesg_restrict.h"

SYSCTL_dmesg_restrict::SYSCTL_dmesg_restrict()
    : GlobalKernelProtection()
{
    this->Sysctl::sysctlParameter = "kernel.dmesg_restrict";
    this->Sysctl::sysctlParameterValue = "1";
    this->policyName = "kernel_dmesg_restrict";
    this->policyTypeValue = std::make_unique<FixedPolicyTypeValue>();
}

bool SYSCTL_dmesg_restrict::check_and_fix()
{
    return this->Sysctl::check_and_fix();
}
