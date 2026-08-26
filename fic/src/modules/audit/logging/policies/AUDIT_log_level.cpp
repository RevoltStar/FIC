#include "modules/audit/logging/policies/AUDIT_log_level.h"

AUDIT_log_level::AUDIT_log_level()
    : AuditLogging()
{
    this->policyName = "log_level";
    const std::vector<std::string> values = {
        "NoLog", "TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"
    };
    this->policyTypeValue = std::make_unique<PossibleListPolicyTypeValue>(values);
}

bool AUDIT_log_level::apply()
{
    if (!this->moduleConf || !this->moduleConf->loadConfig()) {
        return false;
    }
    if (!this->moduleConf->hasConfiguredValue(this->policyName)) {
        return false;
    }
    return this->getValue() != std::nullopt;
}
