#include "modules/global/system_settings/policies/GLOBAL_periodic_apply_settings.h"
#include "modules/global/system_settings/PeriodicApplySettings.h"

namespace {
// Reuse integer editor/restrictions/defaults, rejecting partial numeric parses
// locally rather than changing the validation contract of existing policies.
class SecondsPolicyTypeValue final : public IntPolicyTypeValue {
public:
    SecondsPolicyTypeValue(int minimum, int maximum, int value)
        : IntPolicyTypeValue(minimum, maximum, value), minimum_(minimum), maximum_(maximum) {}
    bool validate(const std::string& value) override {
        return fic::daemon::validPeriodicSeconds(value, minimum_, maximum_);
    }
private:
    int minimum_, maximum_;
};
bool validConfiguration(ModuleConfigFileHandler* config, const std::string& name,
                        PolicyTypeValue& type) {
    if (!config || !config->loadConfig()) return false;
    if (!config->hasPolicyStatus(name) && !config->hasConfiguredValue(name)) return true;
    const auto status = config->ConfigFileHandler::getValue(std::string(name) + ".status");
    return (status == "ENABLE" || status == "DISABLE") &&
        config->hasConfiguredValue(name) && type.validate(config->getPolicyValue(name));
}
}
GLOBAL_check_interval::GLOBAL_check_interval() {
    policyName = "check_interval";
    policyTypeValue = std::make_unique<SecondsPolicyTypeValue>(60, 86400, 1800);
}
bool GLOBAL_check_interval::apply() {
    return validConfiguration(moduleConf.get(), policyName, *policyTypeValue);
}
GLOBAL_periodic_apply_min_pause::GLOBAL_periodic_apply_min_pause() {
    policyName = "periodic_apply_min_pause";
    policyTypeValue = std::make_unique<SecondsPolicyTypeValue>(0, 600, 30);
}
bool GLOBAL_periodic_apply_min_pause::apply() {
    return validConfiguration(moduleConf.get(), policyName, *policyTypeValue);
}
