#include "modules/sysctl/submodules/networkkernelprotection/SYSCTL_tcp_keepalive_time.h"

SYSCTL_tcp_keepalive_time::SYSCTL_tcp_keepalive_time()
    : NetworkKernelProtection()
{
    this->Sysctl::sysctlParameter = "net.ipv4.tcp_keepalive_time";
    this->Sysctl::sysctlParameterValue = "300";
    this->policyName = "tcp_keepalive_time";
    this->policyTypeValue = std::make_unique<IntPolicyTypeValue>(60, 7200, 300);
}

bool SYSCTL_tcp_keepalive_time::apply()
{
    return this->Sysctl::apply();
}
