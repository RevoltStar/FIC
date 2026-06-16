#include "modules/sysctl/submodules/globalkernelprotection/SYSCTL_user_ns_restrict.h"

SYSCTL_user_ns_restrict::SYSCTL_user_ns_restrict()
    : GlobalKernelProtection()
{
    this->Sysctl::sysctlParameter = "user.max_user_namespaces";
    this->Sysctl::sysctlParameterValue = "0";
    this->policyName = "user_namespace_restriction";
    this->policyTypeValue = std::make_unique<IntPolicyTypeValue>(0, 65536, 0);
}

bool SYSCTL_user_ns_restrict::apply()
{
    return this->Sysctl::apply();
}
