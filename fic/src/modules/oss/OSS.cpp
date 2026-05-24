#include "modules/oss/OSS.h"

OSS::OSS()
    :CheckAndFix()
{
    this->moduleName = "OSS";
    this->moduleConf = std::make_unique<ModuleConfigFileHandler>(this->moduleName);
    this->moduleConf->loadConfig();
}
