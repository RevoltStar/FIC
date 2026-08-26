#include "modules/oss/fstab/policies/OSS_fstab_var_log_audit_secure_options.h"

OSS_fstab_var_log_audit_secure_options::OSS_fstab_var_log_audit_secure_options()
    : Fstab()
{
    this->policyName = "fstab_var_log_audit_secure_options";
    this->mountPoints = {"/var/log/audit"};
    this->configureFixedOptions({"rw", "nodev", "nosuid", "noexec", "relatime"});
}
