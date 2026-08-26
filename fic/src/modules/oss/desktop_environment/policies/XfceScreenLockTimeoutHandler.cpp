#include "modules/oss/desktop_environment/policies/XfceScreenLockTimeoutHandler.h"

#include "modules/oss/desktop_environment/backends/BackendCommand.h"

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
    if (!backend.setProperty(CHANNEL, "/saver/enabled", "bool", "true", error) ||
        !backend.setProperty(CHANNEL, "/saver/idle-activation/enabled", "bool", "true", error) ||
        !backend.setProperty(CHANNEL, "/saver/idle-activation/delay", "int", std::to_string(timeoutMinutes), error) ||
        !backend.setProperty(CHANNEL, "/lock/enabled", "bool", "true", error) ||
        !backend.setProperty(CHANNEL, "/lock/saver-activation/enabled", "bool", "true", error) ||
        !backend.setProperty(CHANNEL, "/lock/saver-activation/delay", "int", "0", error)) {
        return false;
    }

    std::string saverEnabled;
    std::string idleEnabled;
    std::string idleDelay;
    std::string lockEnabled;
    std::string lockWithSaverEnabled;
    std::string lockDelay;
    if (!backend.getProperty(CHANNEL, "/saver/enabled", saverEnabled, error) ||
        !backend.getProperty(CHANNEL, "/saver/idle-activation/enabled", idleEnabled, error) ||
        !backend.getProperty(CHANNEL, "/saver/idle-activation/delay", idleDelay, error) ||
        !backend.getProperty(CHANNEL, "/lock/enabled", lockEnabled, error) ||
        !backend.getProperty(CHANNEL, "/lock/saver-activation/enabled", lockWithSaverEnabled, error) ||
        !backend.getProperty(CHANNEL, "/lock/saver-activation/delay", lockDelay, error)) {
        return false;
    }

    bool actualSaverEnabled = false;
    bool actualIdleEnabled = false;
    bool actualLockEnabled = false;
    bool actualLockWithSaverEnabled = false;
    const std::optional<int> actualIdleDelay = desktop_backend::parseInteger(idleDelay);
    const std::optional<int> actualLockDelay = desktop_backend::parseInteger(lockDelay);
    if (!desktop_backend::parseBoolean(saverEnabled, actualSaverEnabled) ||
        !desktop_backend::parseBoolean(idleEnabled, actualIdleEnabled) ||
        !desktop_backend::parseBoolean(lockEnabled, actualLockEnabled) ||
        !desktop_backend::parseBoolean(lockWithSaverEnabled, actualLockWithSaverEnabled) ||
        !actualSaverEnabled || !actualIdleEnabled || !actualLockEnabled || !actualLockWithSaverEnabled ||
        !actualIdleDelay.has_value() || actualIdleDelay.value() != timeoutMinutes ||
        !actualLockDelay.has_value() || actualLockDelay.value() != 0) {
        error = "XFCE screen lock settings did not reach the requested state";
        return false;
    }
    return true;
}
