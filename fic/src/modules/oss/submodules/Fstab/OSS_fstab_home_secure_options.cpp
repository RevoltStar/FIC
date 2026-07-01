#include "modules/oss/submodules/Fstab/OSS_fstab_home_secure_options.h"

OSS_fstab_home_secure_options::OSS_fstab_home_secure_options()
    : Fstab()
{
    this->policyName = "fstab_home_secure_options";
    this->mountPoints = {"/home"};
    this->requiredOptions = {"nodev", "nosuid"};
    this->policyTypeValue = std::make_unique<FixedPolicyTypeValue>();
}
