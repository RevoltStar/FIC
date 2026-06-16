#include "modules/sysctl/submodules/networkkernelprotection/SYSCTL_tcp_max_syn_backlog.h"

SYSCTL_tcp_max_syn_backlog::SYSCTL_tcp_max_syn_backlog()
    : NetworkKernelProtection()
{
    this->Sysctl::sysctlParameter = "net.ipv4.tcp_max_syn_backlog";
    this->Sysctl::sysctlParameterValue = "2048";
    this->policyName = "tcp_max_syn_backlog";
    this->policyTypeValue = std::make_unique<IntPolicyTypeValue>(128, 8192, 2048);
}

bool SYSCTL_tcp_max_syn_backlog::apply()
{
    return this->Sysctl::apply();
}
