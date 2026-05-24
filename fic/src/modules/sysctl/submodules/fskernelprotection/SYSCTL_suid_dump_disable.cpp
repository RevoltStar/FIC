#include "modules/sysctl/submodules/fskernelprotection/SYSCTL_suid_dump_disable.h"

SYSCTL_suid_dump_disable::SYSCTL_suid_dump_disable()
    : FSKernelProtection()
{
    this->Sysctl::sysctlParameter = "fs.suid_dumpable";
    this->Sysctl::sysctlParameterValue = "0";
    this->policyName = "fs_suid_dump_disable";
    this->policyTypeValue = std::make_unique<PossibleListPolicyTypeValue>(
        std::vector<std::string>{"0", "1", "2"});
}

bool SYSCTL_suid_dump_disable::check_and_fix()
{
    return this->Sysctl::check_and_fix();
}
