#include "modules/oss/desktop_environment/policies/GnomeScreenLockTimeoutHandler.h"

#include "modules/oss/desktop_environment/backends/BackendCommand.h"

#include <cstdint>

GnomeScreenLockTimeoutHandler::GnomeScreenLockTimeoutHandler(
    const UserSession& session,
    const SessionContext& context
)
    : backend(session, context)
{
}

bool GnomeScreenLockTimeoutHandler::apply(int timeoutMinutes, std::string& error) const
{
    const std::uint32_t expectedTimeoutSeconds =
        static_cast<std::uint32_t>(timeoutMinutes) * 60U;
    const std::string timeoutSeconds =
        "uint32 " + std::to_string(expectedTimeoutSeconds);
    if (!backend.setSetting("org.gnome.desktop.session", "idle-delay", timeoutSeconds, error) ||
        !backend.setSetting("org.gnome.desktop.screensaver", "lock-enabled", "true", error) ||
        !backend.setSetting("org.gnome.desktop.screensaver", "lock-delay", "uint32 0", error)) {
        return false;
    }

    std::uint32_t idleDelay = 0;
    std::string lockEnabled;
    std::uint32_t lockDelay = 0;
    if (!backend.getUInt32Setting(
            "org.gnome.desktop.session", "idle-delay", idleDelay, error) ||
        !backend.getSetting("org.gnome.desktop.screensaver", "lock-enabled", lockEnabled, error) ||
        !backend.getUInt32Setting(
            "org.gnome.desktop.screensaver", "lock-delay", lockDelay, error)) {
        return false;
    }

    bool actualLockEnabled = false;
    if (!desktop_backend::parseBoolean(lockEnabled, actualLockEnabled)) {
        error = "could not parse GNOME lock-enabled value: " + lockEnabled;
        return false;
    }
    if (idleDelay != expectedTimeoutSeconds) {
        error = "GNOME idle-delay did not reach requested value: expected " +
            std::to_string(expectedTimeoutSeconds) + ", got " +
            std::to_string(idleDelay);
        return false;
    }
    if (!actualLockEnabled) {
        error = "GNOME lock-enabled did not reach requested value: expected true, got false";
        return false;
    }
    if (lockDelay != 0U) {
        error = "GNOME lock-delay did not reach requested value: expected 0, got " +
            std::to_string(lockDelay);
        return false;
    }
    return true;
}
