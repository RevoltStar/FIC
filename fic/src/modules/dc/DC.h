#ifndef DC_H
#define DC_H

#include "core/Policy.h"
#include "utils/ConfigFileHandler.h"
#include <fic/device-db/DB.h>
#include <iostream>

//Класс для работы с устройствами
class DC : public Policy
{
private:
    //Каталог с базой данных контроля устройств
    std::string DC_databasefile;
    //Собственно, сама БД
    DB DC_database;
protected:
    
public:
    //Добавить устройство
    bool add_device();
    //Разрешено ли устройство?
    bool is_allowed();
    //bool
    //Проверить, что используются только разрешенные устройства.
    bool apply () override;
    DC();
};

#endif // D_H
