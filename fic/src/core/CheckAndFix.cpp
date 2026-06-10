#include "CheckAndFix.h"

#include "utils/GlobalConfig.h"

CheckAndFix::CheckAndFix(){

}
CheckAndFix::~CheckAndFix(){

}

std::optional<std::string> CheckAndFix::getGlobalConfigValue(const std::string& parameter){
    return GlobalConfig::getEnabledValue(parameter);
}

bool CheckAndFix::log(std::string message, logLevel logLev){
    if(message.empty()){
       return true;
    }
    return Logger::log(message, logLev, "daemon");
}

bool CheckAndFix::notify(std::string message, notifyLevel notifyLev){
    std::string logName = this->moduleName + "_" + this->policyName;
    return NotifyUser::notify_user(logName, message, notifyLev);
}
