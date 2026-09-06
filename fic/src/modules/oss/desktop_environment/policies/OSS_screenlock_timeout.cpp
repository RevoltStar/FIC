#include "modules/oss/desktop_environment/policies/OSS_screenlock_timeout.h"

#include "modules/oss/desktop_environment/backends/DesktopEnvironmentBackend.h"
#include "modules/oss/desktop_environment/policies/ScreenLockTimeoutHandler.h"
#include <optional>
#include <string>
#include <utility>

OSS_screenlock_timeout::OSS_screenlock_timeout(
    ControlledDesktopEnvironmentScope& scope,
    std::shared_ptr<GraphicalSessionInventory> inventory)
    : SessionAwareDesktopEnvironmentPolicy(scope, std::move(inventory))
{
    this->policyName = "screenlock_timeout";
    this->policyTypeValue = std::make_unique<IntPolicyTypeValue>(1, 20, 5);
}

bool OSS_screenlock_timeout::prepare(std::string& error)
{
    const std::optional<std::string> configuredValue = this->getValue();
    if (!configuredValue.has_value()) {
        error = "screenlock_timeout has no configured value";
        return false;
    }

    try {
        timeoutMinutes_ = std::stoi(configuredValue.value());
    } catch (...) {
        error = "Invalid screen lock timeout value";
        return false;
    }
    error.clear();
    return true;
}

bool OSS_screenlock_timeout::relevantTo(DesktopEnvironmentKind desktop) const
{
    return desktop != DesktopEnvironmentKind::Unknown;
}

EnforcementMode OSS_screenlock_timeout::modeFor(
    DesktopEnvironmentKind desktop) const
{
    return desktop == DesktopEnvironmentKind::Lxqt ||
           desktop == DesktopEnvironmentKind::Unknown
        ? EnforcementMode::Unsupported
        : EnforcementMode::SessionOnly;
}

bool OSS_screenlock_timeout::reconcileControlledSession(
    const ClassifiedGraphicalSession& session,
    std::string& error)
{
    std::unique_ptr<ScreenLockTimeoutHandler> handler =
        ScreenLockTimeoutHandlerFactory::create(
            session.session, session.context);
    if (!handler) {
        error = std::string("screenlock_timeout is not supported for desktop ") +
            DesktopEnvironmentBackend::kindName(session.desktop);
        return false;
    }
    return handler->apply(timeoutMinutes_, error);
}
