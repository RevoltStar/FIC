#include "modules/oss/desktop_environment/policies/GnomeScreenLockTimeoutHandler.h"

#include "modules/oss/desktop_environment/backends/BackendCommand.h"

#include <optional>

GnomeScreenLockTimeoutHandler::GnomeScreenLockTimeoutHandler(
    const UserSession& session,
    const SessionContext& context
)
    : backend(session, context)
{
}

bool GnomeScreenLockTimeoutHandler::apply(int timeoutMinutes, std::string& error) const
{
    const std::string timeoutSeconds = "uint32 " + std::to_string(timeoutMinutes * 60);
    if (!backend.setSetting("org.gnome.desktop.session", "idle-delay", timeoutSeconds, error) ||
        !backend.setSetting("org.gnome.desktop.screensaver", "lock-enabled", "true", error) ||
        !backend.setSetting("org.gnome.desktop.screensaver", "lock-delay", "uint32 0", error)) {
        return false;
    }

    std::string idleDelay;
    std::string lockEnabled;
    std::string lockDelay;
    if (!backend.getSetting("org.gnome.desktop.session", "idle-delay", idleDelay, error) ||
        !backend.getSetting("org.gnome.desktop.screensaver", "lock-enabled", lockEnabled, error) ||
        !backend.getSetting("org.gnome.desktop.screensaver", "lock-delay", lockDelay, error)) {
        return false;
    }

    const std::optional<int> actualIdleDelay = desktop_backend::parseInteger(idleDelay);
    const std::optional<int> actualLockDelay = desktop_backend::parseInteger(lockDelay);
    bool actualLockEnabled = false;
    if (!actualIdleDelay.has_value() || actualIdleDelay.value() != timeoutMinutes * 60 ||
        !actualLockDelay.has_value() || actualLockDelay.value() != 0 ||
        !desktop_backend::parseBoolean(lockEnabled, actualLockEnabled) ||
        !actualLockEnabled) {
        error = "GNOME screen lock settings did not reach the requested state";
        return false;
    }
    return true;
}
