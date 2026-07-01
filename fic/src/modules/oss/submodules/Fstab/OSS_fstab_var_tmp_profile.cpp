#include "modules/oss/submodules/Fstab/OSS_fstab_var_tmp_profile.h"

OSS_fstab_var_tmp_profile::OSS_fstab_var_tmp_profile()
    : Fstab()
{
    this->policyName = "fstab_var_tmp_profile";
    this->mountPoints = {"/var/tmp"};
    this->configureProfiles({
        {"optimal", {"rw", "nodev", "nosuid", "noexec", "relatime"}},
        {"minimal", {"rw", "nodev", "nosuid", "relatime"}}
    });
}
