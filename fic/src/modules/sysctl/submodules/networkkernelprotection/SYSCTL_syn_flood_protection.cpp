#include "modules/sysctl/submodules/networkkernelprotection/SYSCTL_syn_flood_protection.h"

SYSCTL_syn_flood_protection::SYSCTL_syn_flood_protection()
    : NetworkKernelProtection()
{
    this->Sysctl::sysctlParameter = "net.ipv4.tcp_syncookies";
    this->Sysctl::sysctlParameterValue = "1";
    this->policyName = "tcp_syncookies_enable";
    this->policyTypeValue = std::make_unique<FixedPolicyTypeValue>();
}

bool SYSCTL_syn_flood_protection::apply()
{
    return this->Sysctl::apply();
}
