#ifndef SYSCTLEDIT_H
#define SYSCTLEDIT_H

#include "core/CheckAndFix.h"
#include "utils/ConfigFileHandler.h"
#include <string>

//Класс для работы с файлом /etc/sysctl
class Sysctl : public CheckAndFix
{
private:
    static std::string sysctlPath;
    static std::unique_ptr<ConfigFileHandler> sysctlConfig;
protected:
    //Какие параметры мы контролируем?
    std::string sysctlParameter="";
    //Какие значения параметров должны быть для данной настройки
    std::string sysctlParameterValue="";
public:

    //Проверить файл /etc/sysctl и исправить
    bool check_and_fix () override;
    Sysctl();
};

#endif // SYSCTLEDIT_H
