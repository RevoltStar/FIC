#include "modules/sysctl/submodules/globalkernelprotection/SYSCTL_perf_event_paranoid.h"

SYSCTL_perf_event_paranoid::SYSCTL_perf_event_paranoid()
    : GlobalKernelProtection()
{
    this->Sysctl::sysctlParameter = "kernel.perf_event_paranoid";
    this->Sysctl::sysctlParameterValue = "3";
    this->policyName = "kernel_perf_event_paranoid";
    this->policyTypeValue = std::make_unique<PossibleListPolicyTypeValue>(
        std::vector<std::string>{"3", "2", "1", "0", "-1", "4"});
}

bool SYSCTL_perf_event_paranoid::apply()
{
    return this->Sysctl::apply();
}
