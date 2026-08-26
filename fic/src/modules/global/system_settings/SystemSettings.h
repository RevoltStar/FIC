#ifndef SYSTEMSETTINGS_H
#define SYSTEMSETTINGS_H

//Глобальные настройки приложения
#include "modules/global/GLOBAL.h"

class SystemSettings : public Global{
public:
    SystemSettings();
    virtual ~SystemSettings() = default;
};

#endif // SYSTEMSETTINGS_H
