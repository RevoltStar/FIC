#ifndef SYSCTLEDIT_H
#define SYSCTLEDIT_H

#include <fic/policy/Policy.h>
#include <string>

// Base class for policies backed by the procps `sysctl --system` configuration.
class Sysctl : public Policy
{
protected:
    //Какие параметры мы контролируем?
    std::string sysctlParameter="";
    //Какие значения параметров должны быть для данной настройки
    std::string sysctlParameterValue="";
public:

    // Enforce and verify both persistent configuration and the live /proc/sys value.
    bool apply () override;
    Sysctl();
};

#endif // SYSCTLEDIT_H
