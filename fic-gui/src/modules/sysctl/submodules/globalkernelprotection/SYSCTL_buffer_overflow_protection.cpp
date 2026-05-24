#include "modules/sysctl/submodules/globalkernelprotection/SYSCTL_buffer_overflow_protection.h"

SYSCTL_buffer_overflow_protection::SYSCTL_buffer_overflow_protection()
    : GlobalKernelProtection()
{
    this->Sysctl::sysctlParameter = "kernel.exec-shield";
    this->Sysctl::sysctlParameterValue = "1";
    this->policyName = "kernel_exec_shield_enable";
    this->policyTypeValue = std::make_unique<EnableDisablePolicyTypeValue>();
}

bool SYSCTL_buffer_overflow_protection::check_and_fix()
{
    return this->Sysctl::check_and_fix();
}
