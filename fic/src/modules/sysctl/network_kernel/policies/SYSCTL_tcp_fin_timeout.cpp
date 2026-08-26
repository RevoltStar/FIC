#include "modules/sysctl/network_kernel/policies/SYSCTL_tcp_fin_timeout.h"

SYSCTL_tcp_fin_timeout::SYSCTL_tcp_fin_timeout()
    : NetworkKernelProtection()
{
    this->Sysctl::sysctlParameter = "net.ipv4.tcp_fin_timeout";
    this->Sysctl::sysctlParameterValue = "30";
    this->policyName = "tcp_fin_timeout";
    this->policyTypeValue = std::make_unique<IntPolicyTypeValue>(10, 120, 30);
}

bool SYSCTL_tcp_fin_timeout::apply()
{
    return this->Sysctl::apply();
}
