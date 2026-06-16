#ifndef SYSCTL_TCP_MAX_SYN_BACKLOG_H
#define SYSCTL_TCP_MAX_SYN_BACKLOG_H

#include "modules/sysctl/submodules/NetworkKernelProtection.h"

class SYSCTL_tcp_max_syn_backlog : public NetworkKernelProtection
{
public:
    SYSCTL_tcp_max_syn_backlog();
    bool apply() override;
};

#endif // SYSCTL_TCP_MAX_SYN_BACKLOG_H
