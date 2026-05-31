#include "modules/sysctl/submodules/fskernelprotection/SYSCTL_protected_symlinks.h"

SYSCTL_protected_symlinks::SYSCTL_protected_symlinks()
    : FSKernelProtection()
{
    this->Sysctl::sysctlParameter = "fs.protected_symlinks";
    this->Sysctl::sysctlParameterValue = "1";
    this->policyName = "fs_protected_symlinks";
    this->policyTypeValue = std::make_unique<FixedPolicyTypeValue>();
}

bool SYSCTL_protected_symlinks::check_and_fix()
{
    return this->Sysctl::check_and_fix();
}
