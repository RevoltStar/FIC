#include "modules/identity_access/IdentityAccessPolicy.h"

namespace {

std::mutex identityConfigurationMutex;

} // namespace

IdentityAccessPolicy::IdentityAccessPolicy(const char* submodule)
    : Policy() {
    this->moduleName = "IDENTITY_ACCESS";
    this->submoduleName = submodule;
    this->moduleConf =
        std::make_unique<ModuleConfigFileHandler>(this->moduleName);
    this->moduleConf->loadConfig();
}

std::mutex& IdentityAccessPolicy::configurationMutex() {
    return identityConfigurationMutex;
}
