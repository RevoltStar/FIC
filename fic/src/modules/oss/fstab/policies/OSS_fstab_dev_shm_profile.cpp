#include "modules/oss/fstab/policies/OSS_fstab_dev_shm_profile.h"

OSS_fstab_dev_shm_profile::OSS_fstab_dev_shm_profile()
    : Fstab()
{
    this->policyName = "fstab_dev_shm_profile";
    this->mountPoints = {"/dev/shm"};
    this->configureProfiles({
        {"optimal", {"rw", "nodev", "nosuid", "noexec", "mode=1777"}},
        {"minimal", {"rw", "nodev", "nosuid", "mode=1777"}}
    });
}
