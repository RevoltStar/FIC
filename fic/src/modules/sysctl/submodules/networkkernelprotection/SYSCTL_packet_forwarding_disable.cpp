#include "modules/sysctl/submodules/networkkernelprotection/SYSCTL_packet_forwarding_disable.h"

SYSCTL_packet_forwarding_disable::SYSCTL_packet_forwarding_disable()
    :NetworkKernelProtection()
{
    this->Sysctl::sysctlParameter = "net.ipv4.ip_forward";
    this->Sysctl::sysctlParameterValue = "0";
    this->policyName = "ipv4_packet_forwarding_disable";
    this->policyTypeValue = std::make_unique<FixedPolicyTypeValue>();
}

bool SYSCTL_packet_forwarding_disable::check_and_fix (){
    return this->Sysctl::check_and_fix();
}
