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
    DesktopEnvironmentSet controlled;
    std::string error;
    if (!controlledDesktopEnvironments(controlled, error)) {
        log(error, logLevel::ERROR);
        return false;
    }
    return true;
}

bool OSS_controlled_desktop_environments::controlledDesktopEnvironments(
    DesktopEnvironmentSet& controlled,
    std::string& error)
{
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
