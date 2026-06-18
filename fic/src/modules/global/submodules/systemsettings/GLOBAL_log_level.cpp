#include "modules/global/submodules/systemsettings/GLOBAL_log_level.h"

GLOBAL_log_level::GLOBAL_log_level()
    :SystemSettings()
{
    this->policyName = "log_level";
    std::vector<std::string> v = {"NoLog", "TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"};
    this->policyTypeValue = std::make_unique<PossibleListPolicyTypeValue>(v);
}

bool GLOBAL_log_level::apply (){
    if (!this->moduleConf || !this->moduleConf->loadConfig()) {
        return false;
    }

    if (!this->moduleConf->hasConfiguredValue(this->policyName)) {
        return false;
    }

    return this->getValue() != std::nullopt;
}
