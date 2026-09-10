#include "modules/oss/desktop_environment/policies/OSS_screenlock_timeout.h"

#include "modules/oss/desktop_environment/backends/DesktopEnvironmentBackend.h"
#include "modules/oss/desktop_environment/policies/ScreenLockTimeoutHandler.h"
#include <optional>
#include <stdexcept>
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
    return configuredTimeoutMinutes(timeoutMinutes_, error);
}

bool OSS_screenlock_timeout::configuredTimeoutMinutes(
    int& value, std::string& error)
{
    const std::optional<std::string> configuredValue = this->getValue();
    if (!configuredValue.has_value()) {
        error = "screenlock_timeout has no configured value";
        return false;
    }

    try {
        std::size_t consumed = 0;
        value = std::stoi(configuredValue.value(), &consumed);
        if (consumed != configuredValue->size() || value < 1 || value > 20)
            throw std::invalid_argument("out of range");
    } catch (...) {
        error = "Invalid screen lock timeout value";
        return false;
    }
    error.clear();
    return true;
}

bool OSS_screenlock_timeout::globalDesktopPolicyContributions(
    std::vector<GlobalDesktopPolicyContribution>& contributions,
    std::string& error)
{
    contributions.clear();
    const bool gnomeApplicable =
        sessionApplicability(DesktopEnvironmentKind::Gnome, error) ==
        SessionApplicability::Applicable;
    if (!error.empty()) return false;
    const bool kdeApplicable =
        sessionApplicability(DesktopEnvironmentKind::Kde, error) ==
        SessionApplicability::Applicable;
    if (!error.empty()) return false;
    if (!gnomeApplicable && !kdeApplicable) return true;

    int timeoutMinutes = 0;
    if (!configuredTimeoutMinutes(timeoutMinutes, error)) return false;
    const PolicyRef owner{moduleName, submoduleName, policyName};
    const auto add = [&](const char* backend, DesktopEnvironmentKind desktop,
                         const char* setting, std::string value) {
        contributions.push_back({backend, desktop,
                                 owner, {setting}, std::move(value)});
    };
    if (gnomeApplicable) {
        add("gnome", DesktopEnvironmentKind::Gnome,
            "/org/gnome/desktop/session/idle-delay",
            "uint32 " + std::to_string(timeoutMinutes * 60));
        add("gnome", DesktopEnvironmentKind::Gnome,
            "/org/gnome/desktop/screensaver/lock-enabled", "true");
        add("gnome", DesktopEnvironmentKind::Gnome,
            "/org/gnome/desktop/screensaver/lock-delay", "uint32 0");
        // disable-lock-screen=true prevents GNOME Shell from locking at all.
        add("gnome", DesktopEnvironmentKind::Gnome,
            "/org/gnome/desktop/lockdown/disable-lock-screen", "false");
    }
    if (kdeApplicable) {
        add("kde", DesktopEnvironmentKind::Kde,
            "kscreenlockerrc/Daemon/Autolock", "true");
        add("kde", DesktopEnvironmentKind::Kde,
            "kscreenlockerrc/Daemon/Timeout",
            std::to_string(timeoutMinutes));
        add("kde", DesktopEnvironmentKind::Kde,
            "kscreenlockerrc/Daemon/Lock", "true");
        add("kde", DesktopEnvironmentKind::Kde,
            "kscreenlockerrc/Daemon/LockGrace", "0");
        add("kde", DesktopEnvironmentKind::Kde,
            "kscreenlockerrc/Daemon/RequirePassword", "true");
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
    if (desktop == DesktopEnvironmentKind::Gnome ||
        desktop == DesktopEnvironmentKind::Kde)
        return EnforcementMode::MandatoryGlobal;
    if (desktop == DesktopEnvironmentKind::Xfce ||
        desktop == DesktopEnvironmentKind::Fly)
        return EnforcementMode::SessionOnly;
    return EnforcementMode::Unsupported;
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
