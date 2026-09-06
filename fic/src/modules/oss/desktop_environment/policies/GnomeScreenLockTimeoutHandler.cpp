#include "modules/oss/desktop_environment/policies/GnomeScreenLockTimeoutHandler.h"

#include "modules/oss/desktop_environment/backends/BackendCommand.h"
#include "modules/oss/desktop_environment/SessionSettingReconciler.h"

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
    const auto readState = [&](bool& matches, std::string&) {
        std::uint32_t idleDelay = 0, lockDelay = 0;
        std::string lockEnabled;
        if (!backend.getUInt32Setting("org.gnome.desktop.session", "idle-delay", idleDelay, error) ||
            !backend.getSetting("org.gnome.desktop.screensaver", "lock-enabled", lockEnabled, error) ||
            !backend.getUInt32Setting("org.gnome.desktop.screensaver", "lock-delay", lockDelay, error)) return false;
        bool enabled = false;
        matches = desktop_backend::parseBoolean(lockEnabled, enabled) && enabled &&
            idleDelay == expectedTimeoutSeconds && lockDelay == 0U;
        return true;
    };
    const auto writeState = [&](std::string&) {
        return backend.setSetting("org.gnome.desktop.session", "idle-delay", timeoutSeconds, error) &&
            backend.setSetting("org.gnome.desktop.screensaver", "lock-enabled", "true", error) &&
            backend.setSetting("org.gnome.desktop.screensaver", "lock-delay", "uint32 0", error);
    };
    return desktop_policy::reconcileEffectiveSetting(
        readState, writeState,
        "GNOME screen lock settings did not reach the requested state", error);
}
