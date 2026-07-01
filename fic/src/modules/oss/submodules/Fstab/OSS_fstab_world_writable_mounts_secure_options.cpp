#include "modules/oss/submodules/Fstab/OSS_fstab_world_writable_mounts_secure_options.h"

OSS_fstab_world_writable_mounts_secure_options::OSS_fstab_world_writable_mounts_secure_options()
    : Fstab()
{
    this->policyName = "fstab_world_writable_mounts_secure_options";
    this->scope = Scope::WorldWritableMountPoints;
    this->requiredOptions = {"nodev", "nosuid", "noexec"};
    this->policyTypeValue = std::make_unique<FixedPolicyTypeValue>();
}
