#include "modules/oss/desktop_environment/policies/KdeScreenLockTimeoutHandler.h"

#include "modules/oss/desktop_environment/backends/BackendCommand.h"

#include <optional>

namespace {
constexpr const char* CONFIG_FILE = "kscreenlockerrc";
constexpr const char* CONFIG_GROUP = "Daemon";
} // namespace

KdeScreenLockTimeoutHandler::KdeScreenLockTimeoutHandler(
    const UserSession& session,
    const SessionContext& context
)
    : backend(session, context)
{
}

bool KdeScreenLockTimeoutHandler::apply(int timeoutMinutes, std::string& error) const
{
    if (!backend.writeConfig(CONFIG_FILE, CONFIG_GROUP, "Autolock", "true", error) ||
        !backend.writeConfig(CONFIG_FILE, CONFIG_GROUP, "Timeout", std::to_string(timeoutMinutes), error) ||
        !backend.writeConfig(CONFIG_FILE, CONFIG_GROUP, "LockGrace", "0", error) ||
        !backend.writeConfig(CONFIG_FILE, CONFIG_GROUP, "RequirePassword", "true", error)) {
        return false;
    }

    if (!backend.callDbusMethod(
            "org.kde.screensaver",
            "/ScreenSaver",
            "org.kde.screensaver",
            "configure",
            error)) {
        error = "failed to reload KDE screen lock settings: " + error;
        return false;
    }

    std::string autolock;
    std::string timeout;
    std::string lockGrace;
    std::string requirePassword;
    if (!backend.readConfig(CONFIG_FILE, CONFIG_GROUP, "Autolock", autolock, error) ||
        !backend.readConfig(CONFIG_FILE, CONFIG_GROUP, "Timeout", timeout, error) ||
        !backend.readConfig(CONFIG_FILE, CONFIG_GROUP, "LockGrace", lockGrace, error) ||
        !backend.readConfig(CONFIG_FILE, CONFIG_GROUP, "RequirePassword", requirePassword, error)) {
        return false;
    }

    bool autolockEnabled = false;
    bool passwordRequired = false;
    const std::optional<int> actualTimeout = desktop_backend::parseInteger(timeout);
    const std::optional<int> actualLockGrace = desktop_backend::parseInteger(lockGrace);
    if (!desktop_backend::parseBoolean(autolock, autolockEnabled) ||
        !desktop_backend::parseBoolean(requirePassword, passwordRequired) ||
        !autolockEnabled || !passwordRequired ||
        !actualTimeout.has_value() || actualTimeout.value() != timeoutMinutes ||
        !actualLockGrace.has_value() || actualLockGrace.value() != 0) {
        error = "KDE screen lock settings did not reach the requested state";
        return false;
    }
    return true;
}
