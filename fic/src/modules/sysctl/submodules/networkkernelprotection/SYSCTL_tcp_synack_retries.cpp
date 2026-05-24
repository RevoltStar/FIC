#include "modules/sysctl/submodules/networkkernelprotection/SYSCTL_tcp_synack_retries.h"

SYSCTL_tcp_synack_retries::SYSCTL_tcp_synack_retries()
    : NetworkKernelProtection()
{
    this->Sysctl::sysctlParameter = "net.ipv4.tcp_synack_retries";
    this->Sysctl::sysctlParameterValue = "2";
    this->policyName = "tcp_synack_retries";
    this->policyTypeValue = std::make_unique<IntPolicyTypeValue>(1, 7, 2);
}

bool SYSCTL_tcp_synack_retries::check_and_fix()
{
    return this->Sysctl::check_and_fix();
}
