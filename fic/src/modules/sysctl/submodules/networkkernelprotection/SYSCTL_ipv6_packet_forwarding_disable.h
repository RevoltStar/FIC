#ifndef SYSCTL_IPV6_PACKET_FORWARDING_DISABLE_H
#define SYSCTL_IPV6_PACKET_FORWARDING_DISABLE_H

#include "modules/sysctl/submodules/NetworkKernelProtection.h"

class SYSCTL_ipv6_packet_forwarding_disable : public NetworkKernelProtection
{
public:
    SYSCTL_ipv6_packet_forwarding_disable();
    bool check_and_fix() override;
};

#endif // SYSCTL_IPV6_PACKET_FORWARDING_DISABLE_H
