#include "modules/net/NET.h"

Net::Net()
    :CheckAndFix()
{
    this->moduleName = "NET";
    this->moduleConf = std::make_unique<ModuleConfigFileHandler>(this->moduleName);
    this->moduleConf->loadConfig();
}
