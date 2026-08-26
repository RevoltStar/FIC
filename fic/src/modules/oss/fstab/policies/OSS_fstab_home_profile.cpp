#include "modules/oss/fstab/policies/OSS_fstab_home_profile.h"

OSS_fstab_home_profile::OSS_fstab_home_profile()
    : Fstab()
{
    this->policyName = "fstab_home_profile";
    this->mountPoints = {"/home"};
    this->configureProfiles({
        {"optimal", {"rw", "nodev", "nosuid", "relatime"}},
        {"strict", {"rw", "nodev", "nosuid", "noexec", "relatime"}}
    });
}
