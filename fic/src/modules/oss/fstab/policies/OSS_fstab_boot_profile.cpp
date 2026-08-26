#include "modules/oss/fstab/policies/OSS_fstab_boot_profile.h"

OSS_fstab_boot_profile::OSS_fstab_boot_profile()
    : Fstab()
{
    this->policyName = "fstab_boot_profile";
    this->mountPoints = {"/boot"};
    this->configureProfiles({
        {"minimal", {"nodev", "nosuid", "noexec"}},
        {"optimal", {"ro", "nodev", "nosuid", "noexec"}}
    });
}
