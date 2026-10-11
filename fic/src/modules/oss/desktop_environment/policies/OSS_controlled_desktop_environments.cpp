#include "modules/oss/desktop_environment/policies/OSS_controlled_desktop_environments.h"

#include "modules/oss/desktop_environment/ControlledDesktopEnvironmentsPolicyTypeValue.h"

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
    error.clear();
    return true;
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
