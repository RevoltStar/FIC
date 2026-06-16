#ifndef SYSCTL_TCP_SYNACK_RETRIES_H
#define SYSCTL_TCP_SYNACK_RETRIES_H

#include "modules/sysctl/submodules/NetworkKernelProtection.h"

class SYSCTL_tcp_synack_retries : public NetworkKernelProtection
{
public:
    SYSCTL_tcp_synack_retries();
    bool apply() override;
};

#endif // SYSCTL_TCP_SYNACK_RETRIES_H
