#include "modules/sysctl/submodules/globalkernelprotection/SYSCTL_process_limits.h"

SYSCTL_process_limits::SYSCTL_process_limits()
    : GlobalKernelProtection()
{
    this->Sysctl::sysctlParameter = "kernel.pid_max";
    this->Sysctl::sysctlParameterValue = "65536";
    this->policyName = "kernel_pid_max_limit";
    this->policyTypeValue = std::make_unique<IntPolicyTypeValue>(32768, 1048576, 65536);
}

bool SYSCTL_process_limits::apply()
{
    return this->Sysctl::apply();
}
