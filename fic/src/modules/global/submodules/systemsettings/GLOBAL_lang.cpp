#include "modules/global/submodules/systemsettings/GLOBAL_lang.h"

GLOBAL_lang::GLOBAL_lang()
    :SystemSettings()
{
    this->policyName = "lang";
    std::vector<std::string> v = {"ru", "en"};
    this->policyTypeValue = std::make_unique<PossibleListPolicyTypeValue>(v);
}

bool GLOBAL_lang::apply (){
    if (!this->moduleConf || !this->moduleConf->loadConfig()) {
        return false;
    }

    if (!this->moduleConf->isParameterExists(this->policyName)) {
        return false;
    }

    return this->getValue() != std::nullopt;
}
