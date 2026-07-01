#include "modules/oss/submodules/Fstab/OSS_fstab_srv_profile.h"

OSS_fstab_srv_profile::OSS_fstab_srv_profile()
    : Fstab()
{
    this->policyName = "fstab_srv_profile";
    this->mountPoints = {"/srv"};
    this->configureProfiles({
        {"minimal", {"nodev", "nosuid"}},
        {"optimal", {"nodev", "nosuid", "noexec"}}
    });
}
