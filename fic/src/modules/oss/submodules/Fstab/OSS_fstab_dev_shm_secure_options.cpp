#include "modules/oss/submodules/Fstab/OSS_fstab_dev_shm_secure_options.h"

OSS_fstab_dev_shm_secure_options::OSS_fstab_dev_shm_secure_options()
    : Fstab()
{
    this->policyName = "fstab_dev_shm_secure_options";
    this->mountPoints = {"/dev/shm"};
    this->requiredOptions = {"nodev", "nosuid", "noexec"};
    this->policyTypeValue = std::make_unique<FixedPolicyTypeValue>();
}
