#include "modules/sysctl/fs_kernel/policies/SYSCTL_fs_protection.h"

SYSCTL_fs_protection::SYSCTL_fs_protection()
    : FSKernelProtection()
{
    this->Sysctl::sysctlParameter = "fs.protected_hardlinks";
    this->Sysctl::sysctlParameterValue = "1";
    this->policyName = "fs_protected_hardlinks";
    this->policyTypeValue = std::make_unique<FixedPolicyTypeValue>();
}

bool SYSCTL_fs_protection::apply()
{
    return this->Sysctl::apply();
}
