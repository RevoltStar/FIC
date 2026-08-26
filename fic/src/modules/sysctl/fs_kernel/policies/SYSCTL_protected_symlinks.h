#ifndef SYSCTL_PROTECTED_SYMLINKS_H
#define SYSCTL_PROTECTED_SYMLINKS_H

#include "modules/sysctl/fs_kernel/FSKernelProtection.h"

class SYSCTL_protected_symlinks : public FSKernelProtection
{
public:
    SYSCTL_protected_symlinks();
    bool apply() override;
};

#endif // SYSCTL_PROTECTED_SYMLINKS_H
