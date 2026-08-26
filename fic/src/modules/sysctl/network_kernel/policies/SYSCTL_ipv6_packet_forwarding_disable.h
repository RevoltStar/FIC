#ifndef SYSCTL_IPV6_PACKET_FORWARDING_DISABLE_H
#define SYSCTL_IPV6_PACKET_FORWARDING_DISABLE_H

#include "modules/sysctl/network_kernel/NetworkKernelProtection.h"

class SYSCTL_ipv6_packet_forwarding_disable : public NetworkKernelProtection
{
public:
    SYSCTL_ipv6_packet_forwarding_disable();
    bool apply() override;
};

#endif // SYSCTL_IPV6_PACKET_FORWARDING_DISABLE_H
