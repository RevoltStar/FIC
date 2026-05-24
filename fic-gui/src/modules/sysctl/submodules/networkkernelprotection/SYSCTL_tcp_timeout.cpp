#include "modules/sysctl/submodules/networkkernelprotection/SYSCTL_tcp_timeout.h"

SYSCTL_tcp_timeout::SYSCTL_tcp_timeout()
    : NetworkKernelProtection()
{
    this->Sysctl::sysctlParameter = "net.ipv4.tcp_fin_timeout";
    this->Sysctl::sysctlParameterValue = "30";
    this->policyName = "tcp_fin_timeout";
    this->policyTypeValue = std::make_unique<IntPolicyTypeValue>(10, 120, 30);
}

bool SYSCTL_tcp_timeout::check_and_fix()
{
    return this->Sysctl::check_and_fix();
}
