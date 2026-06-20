#ifndef NET_H
#define NET_H

//Класс для модуля "Настройки сетевых сервисов"
#include <fic/policy/Policy.h>
class Net : public Policy
{
public:
    Net();
    virtual ~Net() = default;
};

#endif // NET_H
