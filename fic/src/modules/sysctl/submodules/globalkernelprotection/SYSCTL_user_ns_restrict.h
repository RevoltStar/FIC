#ifndef SYSCTL_USER_NS_RESTRICT_H
#define SYSCTL_USER_NS_RESTRICT_H

#include "modules/sysctl/submodules/GlobalKernelProtection.h"

//Запрет (ограничение) создания пользовательских namespaces
class SYSCTL_user_ns_restrict : public GlobalKernelProtection
{
public:
    SYSCTL_user_ns_restrict();
    bool apply() override;
};

#endif // SYSCTL_USER_NS_RESTRICT_H
