#include "modules/global/lock_settings/GLOBAL_incident_response_mode.h"

GLOBAL_incident_response_mode::GLOBAL_incident_response_mode() : Global() {
    submoduleName = "lock_settings";
    policyName = "incident_response_mode";
    policyTypeValue = std::make_unique<PossibleListPolicyTypeValue>(
        std::vector<std::string>{"PASSIVE", "ACTIVE"});
    addRequiredDependency({"NET", "SshEdit", "ssh_use_pam"},
                          whenOwnerValueEquals("ACTIVE"));
}

bool GLOBAL_incident_response_mode::apply() {
    return moduleConf && moduleConf->loadConfig() &&
        moduleConf->hasConfiguredValue(policyName) && getValue().has_value();
}
