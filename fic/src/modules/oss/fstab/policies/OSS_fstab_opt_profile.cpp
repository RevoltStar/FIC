#include "modules/oss/fstab/policies/OSS_fstab_opt_profile.h"

OSS_fstab_opt_profile::OSS_fstab_opt_profile()
    : Fstab()
{
    this->policyName = "fstab_opt_profile";
    this->mountPoints = {"/opt"};
    this->configureFixedOptions({"nodev"});
}
