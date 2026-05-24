#ifndef SYSCTL_TCP_KEEPALIVE_TIME_H
#define SYSCTL_TCP_KEEPALIVE_TIME_H

#include "modules/sysctl/submodules/NetworkKernelProtection.h"

class SYSCTL_tcp_keepalive_time : public NetworkKernelProtection
{
public:
    SYSCTL_tcp_keepalive_time();
    bool check_and_fix() override;
};

#endif // SYSCTL_TCP_KEEPALIVE_TIME_H
