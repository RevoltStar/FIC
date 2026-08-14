#include "modules/audit/AUDIT.h"

Audit::Audit()
    : Policy()
{
    this->moduleName = "AUDIT";
    this->moduleConf = std::make_unique<ModuleConfigFileHandler>(this->moduleName);
    this->moduleConf->loadConfig();
}

bool Audit::apply()
{
    return true;
}
