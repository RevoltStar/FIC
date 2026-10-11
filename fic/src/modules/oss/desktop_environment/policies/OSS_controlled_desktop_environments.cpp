#include "modules/oss/desktop_environment/policies/OSS_controlled_desktop_environments.h"

#include "modules/oss/desktop_environment/ControlledDesktopEnvironmentsPolicyTypeValue.h"
#include "rollback/DaemonMutationJournal.h"
#include "rollback/ScopeTransition.h"
#include <algorithm>

OSS_controlled_desktop_environments::OSS_controlled_desktop_environments()
    : DesktopEnvironment()
{
    policyName = "controlled_desktop_environments";
    policyTypeValue =
        std::make_unique<ControlledDesktopEnvironmentsPolicyTypeValue>();
}

bool OSS_controlled_desktop_environments::apply()
{
    std::string error;
    if (readyForApply(error)) return true;
    log(error, logLevel::ERROR);
    return false;
}

bool OSS_controlled_desktop_environments::readyForApply(std::string& error)
{
    DesktopEnvironmentSet controlled;
    if (!controlledDesktopEnvironments(controlled, error)) return false;
    if (controlled.empty()) {
        error = "controlled_desktop_environments is empty (UNCONFIGURED)";
        return false;
    }
    auto* journal = fic::rollback::DaemonMutationJournal::instance().tryGet(error);
    if (!journal) {
        if (error.empty()) error = "DE scope journal is unavailable";
        return false;
    }
    std::vector<std::string> configured;
    for (const auto kind : controlled)
        configured.emplace_back(DesktopEnvironmentBackend::kindName(kind));
    std::sort(configured.begin(), configured.end());
    return fic::rollback::ScopeTransition(*journal).requireCommitted(configured, error);
}

bool OSS_controlled_desktop_environments::controlledDesktopEnvironments(
    DesktopEnvironmentSet& controlled,
    std::string& error)
{
    if (!isEnabled()) {
        error = "Required dependency is disabled: OSS/DesktopEnvironment/controlled_desktop_environments";
        return false;
    }
    const std::optional<std::string> configured = getValue();
    if (!configured.has_value() ||
        !ControlledDesktopEnvironmentsPolicyTypeValue::parse(
            configured.value_or(""), controlled)) {
        error = "controlled_desktop_environments has an invalid value";
        return false;
    }
    error.clear();
    return true;
}
