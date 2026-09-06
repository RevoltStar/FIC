#include "modules/oss/desktop_environment/policies/KdeScreenLockTimeoutHandler.h"

#include "modules/oss/desktop_environment/backends/BackendCommand.h"
#include "modules/oss/desktop_environment/SessionSettingReconciler.h"

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
    const auto readState = [&](bool& matches, std::string&) {
        std::string autolock, timeout, lockGrace, requirePassword;
        if (!backend.readConfig(CONFIG_FILE, CONFIG_GROUP, "Autolock", autolock, error) ||
            !backend.readConfig(CONFIG_FILE, CONFIG_GROUP, "Timeout", timeout, error) ||
            !backend.readConfig(CONFIG_FILE, CONFIG_GROUP, "LockGrace", lockGrace, error) ||
            !backend.readConfig(CONFIG_FILE, CONFIG_GROUP, "RequirePassword", requirePassword, error)) return false;
        bool autoEnabled = false, password = false;
        const auto actualTimeout = desktop_backend::parseInteger(timeout);
        const auto grace = desktop_backend::parseInteger(lockGrace);
        matches = desktop_backend::parseBoolean(autolock, autoEnabled) &&
            desktop_backend::parseBoolean(requirePassword, password) &&
            autoEnabled && password && actualTimeout == timeoutMinutes && grace == 0;
        return true;
    };
    const auto writeState = [&](std::string&) {
        if (!backend.writeConfig(CONFIG_FILE, CONFIG_GROUP, "Autolock", "true", error) ||
            !backend.writeConfig(CONFIG_FILE, CONFIG_GROUP, "Timeout", std::to_string(timeoutMinutes), error) ||
            !backend.writeConfig(CONFIG_FILE, CONFIG_GROUP, "LockGrace", "0", error) ||
            !backend.writeConfig(CONFIG_FILE, CONFIG_GROUP, "RequirePassword", "true", error)) return false;
        if (!backend.callDbusMethod(
            "org.kde.screensaver",
            "/ScreenSaver",
            "org.kde.screensaver",
            "configure",
            error)) {
            error = "failed to reload KDE screen lock settings: " + error;
            return false;
        }
        return true;
    };
    return desktop_policy::reconcileEffectiveSetting(
        readState, writeState,
        "KDE screen lock settings did not reach the requested state", error);
}
