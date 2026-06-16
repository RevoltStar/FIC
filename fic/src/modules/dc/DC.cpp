#include "modules/dc/DC.h"
#include <exception>

DC::DC()
    :Policy(), DC_database(DB("/opt/fic/db/devices.db")){
    this->moduleName = "DC";
    this->moduleConf = std::make_unique<ModuleConfigFileHandler>(this->moduleName);
    this->moduleConf->loadConfig();
    //Каталог с базой данных контроля устройств
    DC_databasefile = "/opt/fic/dc/devices.db";
}


//
bool DC::apply (){
    return true;
}
