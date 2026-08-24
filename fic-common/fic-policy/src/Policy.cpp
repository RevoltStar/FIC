#include <fic/policy/Policy.h>

#include <utility>

Policy::Policy(){

}
Policy::~Policy(){

}

void Policy::addRequiredDependency(const PolicyRef& policy) {
    addRequiredDependency(policy, {});
}

void Policy::addRequiredDependency(
    const PolicyRef& policy,
    const PolicyDependencyCondition& condition) {
    addDependency(policy, PolicyDependencyStrength::Required, condition);
}

void Policy::addRecommendedDependency(const PolicyRef& policy) {
    addRecommendedDependency(policy, {});
}

void Policy::addRecommendedDependency(
    const PolicyRef& policy,
    const PolicyDependencyCondition& condition) {
    addDependency(policy, PolicyDependencyStrength::Recommended, condition);
}

const std::vector<PolicyDependency>& Policy::dependencies() const {
    return dependencies_;
}

void Policy::addDependency(
    const PolicyRef& policy,
    PolicyDependencyStrength strength,
    const PolicyDependencyCondition& condition) {
    if (dependenciesFrozen_) {
        throw std::logic_error(
            "policy dependency metadata is already frozen: " + policyName);
    }
    dependencies_.push_back({policy, strength, condition});
}

void Policy::freezeDependencies() {
    dependenciesFrozen_ = true;
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
