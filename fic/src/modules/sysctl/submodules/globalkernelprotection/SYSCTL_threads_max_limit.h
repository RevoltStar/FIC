#ifndef SYSCTL_THREADS_MAX_LIMIT_H
#define SYSCTL_THREADS_MAX_LIMIT_H

#include "modules/sysctl/submodules/GlobalKernelProtection.h"

class SYSCTL_threads_max_limit : public GlobalKernelProtection
{
public:
    SYSCTL_threads_max_limit();
    bool apply() override;
};

#endif // SYSCTL_THREADS_MAX_LIMIT_H
