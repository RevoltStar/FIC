#include "modules/oss/submodules/Fstab/OSS_fstab_no_insecure_options.h"

OSS_fstab_no_insecure_options::OSS_fstab_no_insecure_options()
    : Fstab()
{
    this->policyName = "fstab_no_insecure_options";
    this->mountPoints = {"/tmp", "/var/tmp", "/dev/shm", "/media", "/mnt", "/run/media"};
    this->requiredOptions = {"nodev", "nosuid", "noexec"};
    this->policyTypeValue = std::make_unique<FixedPolicyTypeValue>();
}
