#include "modules/sysctl/submodules/globalkernelprotection/SYSCTL_threads_max_limit.h"

SYSCTL_threads_max_limit::SYSCTL_threads_max_limit()
    : GlobalKernelProtection()
{
    this->Sysctl::sysctlParameter = "kernel.threads-max";
    this->Sysctl::sysctlParameterValue = "4096";
    this->policyName = "kernel_threads_max_limit";
    this->policyTypeValue = std::make_unique<IntPolicyTypeValue>(1024, 262144, 4096);
}

bool SYSCTL_threads_max_limit::apply()
{
    return this->Sysctl::apply();
}
