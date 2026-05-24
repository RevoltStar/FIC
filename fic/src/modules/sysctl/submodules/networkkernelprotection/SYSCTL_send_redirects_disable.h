#ifndef SYSCTL_SEND_REDIRECTS_DISABLE_H
#define SYSCTL_SEND_REDIRECTS_DISABLE_H

#include "modules/sysctl/submodules/NetworkKernelProtection.h"


class SYSCTL_send_redirects_disable : public NetworkKernelProtection
{
public:
    SYSCTL_send_redirects_disable();
    bool check_and_fix() override;
};

#endif // SYSCTL_SEND_REDIRECTS_DISABLE_H
