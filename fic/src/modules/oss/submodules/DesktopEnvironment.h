#ifndef DESKTOPENVIRONMENT_H
#define DESKTOPENVIRONMENT_H

#include "modules/oss/OSS.h"

//Класс для работы с графическим окружением (определение, редактирование настроек)
class DesktopEnvironment : public OSS
{
public:
    DesktopEnvironment();
    virtual ~DesktopEnvironment() = default;


    //Определить графическую оболочку
    std::string detectDE();
    bool check_and_fix () override;
};

#endif // DESKTOPENVIRONMENT_H
