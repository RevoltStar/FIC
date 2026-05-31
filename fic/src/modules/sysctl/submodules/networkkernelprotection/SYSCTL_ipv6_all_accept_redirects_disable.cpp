#include "modules/sysctl/submodules/networkkernelprotection/SYSCTL_ipv6_all_accept_redirects_disable.h"

SYSCTL_ipv6_all_accept_redirects_disable::SYSCTL_ipv6_all_accept_redirects_disable()
    : NetworkKernelProtection()
{
    this->Sysctl::sysctlParameter = "net.ipv6.conf.all.accept_redirects";
    this->Sysctl::sysctlParameterValue = "0";
    this->policyName = "ipv6_all_accept_redirects_disable";
    this->policyTypeValue = std::make_unique<FixedPolicyTypeValue>();
}

bool SYSCTL_ipv6_all_accept_redirects_disable::check_and_fix()
{
    return this->Sysctl::check_and_fix();
}
