#include "modules/auth/AUTH.h"

Auth::Auth()
    : Policy() {
    this->moduleName = "AUTH";
    this->moduleConf =
        std::make_unique<ModuleConfigFileHandler>(this->moduleName);
    this->moduleConf->loadConfig();
}
