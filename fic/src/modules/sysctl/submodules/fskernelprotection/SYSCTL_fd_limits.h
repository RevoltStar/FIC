#ifndef SYSCTL_FD_LIMITS_H
#define SYSCTL_FD_LIMITS_H

#include "modules/sysctl/submodules/FSKernelProtection.h"

class SYSCTL_fd_limits : public FSKernelProtection
{
public:
    SYSCTL_fd_limits();
    bool apply() override;

private:
    static constexpr unsigned int MAX_FD_LIMIT = 786144;
};

#endif // SYSCTL_FD_LIMITS_H
