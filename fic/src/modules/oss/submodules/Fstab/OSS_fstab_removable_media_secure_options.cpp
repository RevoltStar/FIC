#include "modules/oss/submodules/Fstab/OSS_fstab_removable_media_secure_options.h"

OSS_fstab_removable_media_secure_options::OSS_fstab_removable_media_secure_options()
    : Fstab()
{
    this->policyName = "fstab_removable_media_secure_options";
    this->mountPoints = {"/media", "/mnt", "/run/media"};
    this->requiredOptions = {"nodev", "nosuid", "noexec"};
    this->policyTypeValue = std::make_unique<FixedPolicyTypeValue>();
}
