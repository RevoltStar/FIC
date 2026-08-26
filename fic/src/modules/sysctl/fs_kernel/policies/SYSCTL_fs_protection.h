#ifndef SYSCTL_FS_PROTECTION_H
#define SYSCTL_FS_PROTECTION_H

#include "modules/sysctl/fs_kernel/FSKernelProtection.h"

class SYSCTL_fs_protection : public FSKernelProtection
{
public:
    SYSCTL_fs_protection();
    bool apply() override;
};


#endif // SYSCTL_FS_PROTECTION_H
