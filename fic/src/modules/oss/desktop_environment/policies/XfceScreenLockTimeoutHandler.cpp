#include "modules/oss/desktop_environment/policies/XfceScreenLockTimeoutHandler.h"

#include "modules/oss/desktop_environment/backends/BackendCommand.h"
#include "modules/oss/desktop_environment/SessionSettingReconciler.h"

#include <optional>

namespace {
constexpr const char* CHANNEL = "xfce4-screensaver";
} // namespace

XfceScreenLockTimeoutHandler::XfceScreenLockTimeoutHandler(
    const UserSession& session,
    const SessionContext& context
)
    : backend(session, context)
{
}

bool XfceScreenLockTimeoutHandler::apply(int timeoutMinutes, std::string& error) const
{
    const auto readState = [&](bool& matches, std::string&) {
        std::string saver, idle, idleDelay, lock, lockSaver, lockDelay;
        if (!backend.getProperty(CHANNEL, "/saver/enabled", saver, error) ||
            !backend.getProperty(CHANNEL, "/saver/idle-activation/enabled", idle, error) ||
            !backend.getProperty(CHANNEL, "/saver/idle-activation/delay", idleDelay, error) ||
            !backend.getProperty(CHANNEL, "/lock/enabled", lock, error) ||
            !backend.getProperty(CHANNEL, "/lock/saver-activation/enabled", lockSaver, error) ||
            !backend.getProperty(CHANNEL, "/lock/saver-activation/delay", lockDelay, error)) return false;
        bool a=false,b=false,c=false,d=false;
        matches = desktop_backend::parseBoolean(saver,a) && desktop_backend::parseBoolean(idle,b) &&
            desktop_backend::parseBoolean(lock,c) && desktop_backend::parseBoolean(lockSaver,d) &&
            a && b && c && d && desktop_backend::parseInteger(idleDelay) == timeoutMinutes &&
            desktop_backend::parseInteger(lockDelay) == 0;
        return true;
    };
    const auto writeState = [&](std::string&) {
        return backend.setProperty(CHANNEL, "/saver/enabled", "bool", "true", error) &&
            backend.setProperty(CHANNEL, "/saver/idle-activation/enabled", "bool", "true", error) &&
            backend.setProperty(CHANNEL, "/saver/idle-activation/delay", "int", std::to_string(timeoutMinutes), error) &&
            backend.setProperty(CHANNEL, "/lock/enabled", "bool", "true", error) &&
            backend.setProperty(CHANNEL, "/lock/saver-activation/enabled", "bool", "true", error) &&
            backend.setProperty(CHANNEL, "/lock/saver-activation/delay", "int", "0", error);
    };
    return desktop_policy::reconcileEffectiveSetting(
        readState, writeState,
        "XFCE screen lock settings did not reach the requested state", error);
}
