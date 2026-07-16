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

    // Check the effective persistent configuration and add a managed override.
    bool apply () override;
    Sysctl();
};

#endif // SYSCTLEDIT_H
