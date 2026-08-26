#ifndef SYSCTL_TCP_KEEPALIVE_TIME_H
#define SYSCTL_TCP_KEEPALIVE_TIME_H

#include "modules/sysctl/network_kernel/NetworkKernelProtection.h"

class SYSCTL_tcp_keepalive_time : public NetworkKernelProtection
{
public:
    SYSCTL_tcp_keepalive_time();
    bool apply() override;
};

#endif // SYSCTL_TCP_KEEPALIVE_TIME_H
