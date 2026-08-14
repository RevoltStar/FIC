#include <fic/policy/Policy.h>

Policy::Policy(){

}
Policy::~Policy(){

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
