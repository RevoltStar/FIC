#ifndef DESKTOPENVIRONMENT_H
#define DESKTOPENVIRONMENT_H

#include "modules/oss/OSS.h"

//Класс для работы с графическим окружением
//(определение настроек производится с помощью агента)
class DesktopEnvironment : public OSS
{
public:
    DesktopEnvironment();
    virtual ~DesktopEnvironment() = default;

    bool apply () override;
};

#endif // DESKTOPENVIRONMENT_H
