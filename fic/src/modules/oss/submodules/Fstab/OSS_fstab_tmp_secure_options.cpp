#include "modules/oss/submodules/Fstab/OSS_fstab_tmp_secure_options.h"

OSS_fstab_tmp_secure_options::OSS_fstab_tmp_secure_options()
    : Fstab()
{
    this->policyName = "fstab_tmp_secure_options";
    this->mountPoints = {"/tmp"};
    this->requiredOptions = {"nodev", "nosuid", "noexec"};
    this->policyTypeValue = std::make_unique<FixedPolicyTypeValue>();
}
