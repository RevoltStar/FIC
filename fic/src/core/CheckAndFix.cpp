#include "CheckAndFix.h"

CheckAndFix::CheckAndFix(){

}
CheckAndFix::~CheckAndFix(){

}

bool CheckAndFix::log(std::string message, logLevel logLev){
    if(message.empty()){
       return true;
    }
    return Logger::log(message, logLev, "daemon");
}

bool CheckAndFix::notifyToUser(std::string message, notifyLevel notifyLev){
    std::string logName = this->moduleName + "_" + this->policyName;
    return NotifyUser::notify_user(logName, message, notifyLev);
}
