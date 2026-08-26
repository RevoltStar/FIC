#ifndef SYSCTL_PACKET_FORWARDING_DISABLE_H
#define SYSCTL_PACKET_FORWARDING_DISABLE_H

#include "modules/sysctl/network_kernel/NetworkKernelProtection.h"

//Отключение пересылки пакетов
class SYSCTL_packet_forwarding_disable : public NetworkKernelProtection
{
public:
    SYSCTL_packet_forwarding_disable();
    bool apply () override;
};

#endif // SYSCTL_PACKET_FORWARDING_DISABLE_H
