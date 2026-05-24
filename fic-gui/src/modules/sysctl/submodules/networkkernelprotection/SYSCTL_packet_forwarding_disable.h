#ifndef SYSCTL_PACKET_FORWARDING_DISABLE_H
#define SYSCTL_PACKET_FORWARDING_DISABLE_H

#include "modules/sysctl/submodules/NetworkKernelProtection.h"

//Отключение пересылки пакетов
class SYSCTL_packet_forwarding_disable : public NetworkKernelProtection
{
public:
    SYSCTL_packet_forwarding_disable();
    bool check_and_fix () override;
};

#endif // SYSCTL_PACKET_FORWARDING_DISABLE_H
