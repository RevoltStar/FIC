#include "modules/sysctl/fs_kernel/policies/SYSCTL_suid_dump_disable.h"

SYSCTL_suid_dump_disable::SYSCTL_suid_dump_disable()
    : FSKernelProtection()
{
    this->Sysctl::sysctlParameter = "fs.suid_dumpable";
    this->Sysctl::sysctlParameterValue = "0";
    this->policyName = "fs_suid_dump_disable";
    this->policyTypeValue = std::make_unique<PossibleListPolicyTypeValue>(
        std::vector<std::string>{"0", "1", "2"});
}

bool SYSCTL_suid_dump_disable::apply()
{
    return this->Sysctl::apply();
}
