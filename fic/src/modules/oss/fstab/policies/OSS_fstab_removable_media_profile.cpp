#include "modules/oss/fstab/policies/OSS_fstab_removable_media_profile.h"

OSS_fstab_removable_media_profile::OSS_fstab_removable_media_profile()
    : Fstab()
{
    this->policyName = "fstab_removable_media_profile";
    this->mountPoints = {"/media", "/mnt", "/run/media"};
    this->configureProfiles({
        {"optimal", {"nodev", "nosuid", "noexec"}},
        {"strict", {"ro", "nodev", "nosuid", "noexec"}}
    });
}
