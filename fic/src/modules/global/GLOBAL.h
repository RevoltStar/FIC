#ifndef GLOBAL_H
#define GLOBAL_H

//Глобальные настройки приложения
#include "core/Policy.h"
class Global : public Policy
{
public:
    Global();
    virtual ~Global() = default;

    bool apply () override;
};

#endif // GLOBAL_H
