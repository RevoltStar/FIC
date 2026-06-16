#include "modules/global/GLOBAL.h"

Global::Global()
    :Policy()
{
    this->moduleName = "GLOBAL";
    this->moduleConf = std::make_unique<ModuleConfigFileHandler>(this->moduleName);
    this->moduleConf->loadConfig();
}

bool Global::apply (){
    return true;
}
