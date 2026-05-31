#include "modules/sysctl/submodules/fskernelprotection/SYSCTL_fs_protection.h"

SYSCTL_fs_protection::SYSCTL_fs_protection()
    : FSKernelProtection()
{
    this->Sysctl::sysctlParameter = "fs.protected_hardlinks";
    this->Sysctl::sysctlParameterValue = "1";
    this->policyName = "fs_protected_hardlinks";
    this->policyTypeValue = std::make_unique<FixedPolicyTypeValue>();
}

bool SYSCTL_fs_protection::check_and_fix()
{
    return this->Sysctl::check_and_fix();
}
