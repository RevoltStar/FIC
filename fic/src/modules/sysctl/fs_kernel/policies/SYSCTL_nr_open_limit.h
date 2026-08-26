#ifndef SYSCTL_NR_OPEN_LIMIT_H
#define SYSCTL_NR_OPEN_LIMIT_H

#include "modules/sysctl/fs_kernel/FSKernelProtection.h"

class SYSCTL_nr_open_limit : public FSKernelProtection
{
public:
    SYSCTL_nr_open_limit();
    bool apply() override;

private:
    static constexpr unsigned int MAX_FD_LIMIT = 786144;
};

#endif // SYSCTL_NR_OPEN_LIMIT_H
