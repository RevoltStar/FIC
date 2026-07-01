#include "modules/oss/submodules/Fstab/OSS_fstab_var_log_secure_options.h"

OSS_fstab_var_log_secure_options::OSS_fstab_var_log_secure_options()
    : Fstab()
{
    this->policyName = "fstab_var_log_secure_options";
    this->mountPoints = {"/var/log"};
    this->configureFixedOptions({"rw", "nodev", "nosuid", "noexec", "relatime"});
}
