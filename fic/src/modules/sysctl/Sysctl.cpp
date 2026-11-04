#include "modules/sysctl/Sysctl.h"
#include "modules/sysctl/SysctlConfiguration.h"
#include "modules/sysctl/SysctlRuntime.h"
#include "modules/sysctl/SysctlTransaction.h"
#include "modules/sysctl/SysctlSystemd.h"
#include "rollback/DaemonMutationJournal.h"

#include <mutex>
#include <optional>
#include <utility>


Sysctl::Sysctl()
    :Policy(){
    this->moduleName = "SYSCTL";
    this->moduleConf = std::make_unique<ModuleConfigFileHandler>(this->moduleName);
    this->moduleConf->loadConfig();
}

void Sysctl::setPlatformConfig(fic::platform::SysctlPlatformConfig platformConfig) {
    platformConfig_ = std::move(platformConfig);
}


// Correct the effective persistent configuration for one sysctl parameter.
bool Sysctl::apply (){
    this->log("Запущена проверка политики " + this->policyName, logLevel::INFO);
    if (this->Sysctl::sysctlParameter.empty()){
        this->log("Имя контролируемого параметра пусто", logLevel::ERROR);
        return false;
    }
    const std::string param = this->Sysctl::sysctlParameter;
    std::string value;

    if(dynamic_cast<FixedPolicyTypeValue*>(this->policyTypeValue.get()) != nullptr){
        /*Для FIXED политики берем из класса*/
        value = this->Sysctl::sysctlParameterValue;
    }else if(dynamic_cast<IntPolicyTypeValue*>(this->policyTypeValue.get()) != nullptr ||
            dynamic_cast<PossibleListPolicyTypeValue*>(this->policyTypeValue.get()) != nullptr){
            /*Для IntPolicyTypeValue или PossibleListPolicyTypeValue политики берем из класса*/
            std::optional valueOpt = this->getValue();
            if(!valueOpt){
                this->log("Reference value for policy " + this->policyName + " is empty", logLevel::ERROR);
                return false;
            }
            value = *valueOpt;
    }else{
        this->log("Unsupported policyTypeValue for sysctl policy " + this->policyName, logLevel::ERROR);
        return false;
    }

    if(!platformConfig_) {this->log("SYSCTL platform unavailable",logLevel::ERROR);return false;}
    std::string error;auto* journal=fic::rollback::DaemonMutationJournal::instance().tryGet(error);
    if(!journal){this->log(error,logLevel::ERROR);return false;}
    const auto profile=fic::platform::makeBuildPlatformProfile();
    fic::platform::PlatformExecutableResolver resolver(profile.executables);
    SysctlConfigurationOptions options;options.platform=*platformConfig_;
    const auto result=applySysctlOwned(*journal,policyRef(),param,value,options,{},
        [&](std::string& reason){return sysctlLoaderAdmission(resolver,reason);});
    this->log(result.message,result.ok?logLevel::INFO:logLevel::ERROR);
    return result.ok;
}
