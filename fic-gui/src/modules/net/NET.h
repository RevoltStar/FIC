#ifndef NET_H
#define NET_H

//Класс для модуля "Настройки сетевых сервисов"
#include "core/CheckAndFix.h"
class Net : public CheckAndFix
{
public:
    Net();
    virtual ~Net() = default;
};

#endif // NET_H
