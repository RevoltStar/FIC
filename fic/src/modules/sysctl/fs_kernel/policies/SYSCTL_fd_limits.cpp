#include "modules/sysctl/fs_kernel/policies/SYSCTL_fd_limits.h"
#include <string>

SYSCTL_fd_limits::SYSCTL_fd_limits()
    : FSKernelProtection()
{
    this->Sysctl::sysctlParameter = "fs.file-max";
    this->Sysctl::sysctlParameterValue = std::to_string(MAX_FD_LIMIT);
    this->policyName = "fs_file_max_limit";
    this->policyTypeValue = std::make_unique<IntPolicyTypeValue>(65536, 2097152, MAX_FD_LIMIT);

}

bool SYSCTL_fd_limits::apply()
{
    return this->Sysctl::apply();
}
