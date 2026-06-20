#include <fic/policy/Policy.h>

#include <fic/core/GlobalConfig.h>

Policy::Policy(){

}
Policy::~Policy(){

}

std::optional<std::string> Policy::getGlobalConfigValue(const std::string& parameter){
    return GlobalConfig::getEnabledValue(parameter);
}

bool Policy::log(std::string message, logLevel logLev){
    if(message.empty()){
       return true;
    }
    return Logger::log(message, logLev, "daemon");
}

bool Policy::notify(std::string message, notifyLevel notifyLev){
    std::string logName = this->moduleName + "_" + this->policyName;
    return NotifyUser::notify_user(logName, message, notifyLev);
}
