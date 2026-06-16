#include "modules/sysctl/submodules/globalkernelprotection/SYSCTL_ptrace_restrict.h"

SYSCTL_ptrace_restrict::SYSCTL_ptrace_restrict()
    : GlobalKernelProtection()
{
    this->Sysctl::sysctlParameter = "kernel.yama.ptrace_scope";
    this->Sysctl::sysctlParameterValue = "2";
    this->policyName = "ptrace_proc_restriction";
    this->policyTypeValue = std::make_unique<PossibleListPolicyTypeValue>(
        std::vector<std::string>{"2", "0", "1", "3"});
}

bool SYSCTL_ptrace_restrict::apply()
{
    return this->Sysctl::apply();
}
