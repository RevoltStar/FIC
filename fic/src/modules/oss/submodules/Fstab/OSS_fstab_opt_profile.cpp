#include "modules/oss/submodules/Fstab/OSS_fstab_opt_profile.h"

OSS_fstab_opt_profile::OSS_fstab_opt_profile()
    : Fstab()
{
    this->policyName = "fstab_opt_profile";
    this->mountPoints = {"/opt"};
    this->configureProfiles({
        {"minimal", {"nodev"}},
        {"optimal", {"ro", "nodev", "exec"}}
    });
}
