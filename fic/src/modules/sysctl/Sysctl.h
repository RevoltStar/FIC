#ifndef SYSCTLEDIT_H
#define SYSCTLEDIT_H

#include <fic/policy/Policy.h>
#include "platform/PlatformProfile.h"

#include <optional>
#include <string>

// Base class for policies backed by the platform-selected sysctl loader.
class Sysctl : public Policy
{
protected:
    //Какие параметры мы контролируем?
    std::string sysctlParameter="";
    //Какие значения параметров должны быть для данной настройки
    std::string sysctlParameterValue="";
    std::optional<fic::platform::SysctlPlatformConfig> platformConfig_;
public:

    // Enforce and verify both persistent configuration and the live /proc/sys value.
    bool apply () override;
    Sysctl();
    void setPlatformConfig(fic::platform::SysctlPlatformConfig platformConfig);
};

#endif // SYSCTLEDIT_H
