#include "modules/global/GLOBAL.h"

Global::Global()
    :CheckAndFix()
{
    this->moduleName = "GLOBAL";
    this->moduleConf = std::make_unique<ModuleConfigFileHandler>(this->moduleName);
    this->moduleConf->loadConfig();
}

bool Global::check_and_fix (){
    return true;
}
