#include "modules/sysctl/submodules/networkkernelprotection/SYSCTL_redirects_disable.h"

SYSCTL_redirects_disable::SYSCTL_redirects_disable()
    : NetworkKernelProtection()
{
    this->Sysctl::sysctlParameter = "net.ipv4.conf.all.accept_redirects";
    this->Sysctl::sysctlParameterValue = "0";
    this->policyName = "ipv4_all_accept_redirects_disable";
    this->policyTypeValue = std::make_unique<FixedPolicyTypeValue>();
}

bool SYSCTL_redirects_disable::apply()
{
    return this->Sysctl::apply();
}
