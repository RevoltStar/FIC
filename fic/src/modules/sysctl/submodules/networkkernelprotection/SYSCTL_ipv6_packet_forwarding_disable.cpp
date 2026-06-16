#include "modules/sysctl/submodules/networkkernelprotection/SYSCTL_ipv6_packet_forwarding_disable.h"

SYSCTL_ipv6_packet_forwarding_disable::SYSCTL_ipv6_packet_forwarding_disable()
    : NetworkKernelProtection()
{
    this->Sysctl::sysctlParameter = "net.ipv6.conf.all.forwarding";
    this->Sysctl::sysctlParameterValue = "0";
    this->policyName = "ipv6_packet_forwarding_disable";
    this->policyTypeValue = std::make_unique<FixedPolicyTypeValue>();
}

bool SYSCTL_ipv6_packet_forwarding_disable::apply()
{
    return this->Sysctl::apply();
}
