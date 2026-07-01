#include "modules/oss/submodules/Fstab/OSS_fstab_tmp_profile.h"

OSS_fstab_tmp_profile::OSS_fstab_tmp_profile()
    : Fstab()
{
    this->policyName = "fstab_tmp_profile";
    this->mountPoints = {"/tmp"};
    this->configureProfiles({
        {"optimal", {"rw", "nodev", "nosuid", "noexec", "relatime"}},
        {"minimal", {"rw", "nodev", "nosuid", "relatime"}}
    });
}
