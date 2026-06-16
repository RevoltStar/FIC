#ifndef SYSCTL_TCP_TIMEOUTS_H
#define SYSCTL_TCP_TIMEOUTS_H

#include "modules/sysctl/submodules/NetworkKernelProtection.h"

class SYSCTL_tcp_timeout : public NetworkKernelProtection
{
public:
    SYSCTL_tcp_timeout();
    bool apply() override;
};

#endif // SYSCTL_TCP_TIMEOUTS_H
