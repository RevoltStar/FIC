#ifndef SYSCTL_TCP_FIN_TIMEOUTS_H
#define SYSCTL_TCP_FIN_TIMEOUTS_H

#include "modules/sysctl/network_kernel/NetworkKernelProtection.h"

class SYSCTL_tcp_fin_timeout : public NetworkKernelProtection
{
public:
    SYSCTL_tcp_fin_timeout();
    bool apply() override;
};

#endif // SYSCTL_TCP_FIN_TIMEOUTS_H
