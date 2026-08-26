#include "modules/sysctl/global_kernel/policies/SYSCTL_sysrq_disable.h"

SYSCTL_sysrq_disable::SYSCTL_sysrq_disable()
    : GlobalKernelProtection()
{
    this->Sysctl::sysctlParameter = "kernel.sysrq";
    this->Sysctl::sysctlParameterValue = "0";
    this->policyName = "kernel_sysrq_disable";
    this->policyTypeValue = std::make_unique<FixedPolicyTypeValue>();
}

bool SYSCTL_sysrq_disable::apply()
{
    return this->Sysctl::apply();
}
