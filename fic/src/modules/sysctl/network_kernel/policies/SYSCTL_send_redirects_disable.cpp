#include "modules/sysctl/network_kernel/policies/SYSCTL_send_redirects_disable.h"

SYSCTL_send_redirects_disable::SYSCTL_send_redirects_disable()
    : NetworkKernelProtection()
{
    this->Sysctl::sysctlParameter = "net.ipv4.conf.all.send_redirects";
    this->Sysctl::sysctlParameterValue = "0";
    this->policyName = "ipv4_all_send_redirects_disable";
    this->policyTypeValue = std::make_unique<FixedPolicyTypeValue>();
}

bool SYSCTL_send_redirects_disable::apply()
{
    return this->Sysctl::apply();
}
