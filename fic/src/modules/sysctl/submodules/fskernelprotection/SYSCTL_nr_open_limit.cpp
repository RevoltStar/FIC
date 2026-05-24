#include "modules/sysctl/submodules/fskernelprotection/SYSCTL_nr_open_limit.h"
#include <string>

SYSCTL_nr_open_limit::SYSCTL_nr_open_limit()
    : FSKernelProtection()
{
    this->Sysctl::sysctlParameter = "fs.nr_open";
    this->Sysctl::sysctlParameterValue = std::to_string(MAX_FD_LIMIT);
    this->policyName = "fs_nr_open_limit";
    this->policyTypeValue = std::make_unique<IntPolicyTypeValue>(65536, 2097152, MAX_FD_LIMIT);
}

bool SYSCTL_nr_open_limit::check_and_fix()
{
    return this->Sysctl::check_and_fix();
}
