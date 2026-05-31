#include "modules/sysctl/submodules/networkkernelprotection/SYSCTL_ipv4_default_send_redirects_disable.h"

SYSCTL_ipv4_default_send_redirects_disable::SYSCTL_ipv4_default_send_redirects_disable()
    : NetworkKernelProtection()
{
    this->Sysctl::sysctlParameter = "net.ipv4.conf.default.send_redirects";
    this->Sysctl::sysctlParameterValue = "0";
    this->policyName = "ipv4_default_send_redirects_disable";
    this->policyTypeValue = std::make_unique<FixedPolicyTypeValue>();
}

bool SYSCTL_ipv4_default_send_redirects_disable::check_and_fix()
{
    return this->Sysctl::check_and_fix();
}
