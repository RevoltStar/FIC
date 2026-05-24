#ifndef GLOBAL_H
#define GLOBAL_H

//Глобальные настройки приложения
#include "core/CheckAndFix.h"
class Global : public CheckAndFix
{
public:
    Global();
    virtual ~Global() = default;

    bool check_and_fix () override;
};

#endif // GLOBAL_H
