#include "modules/oss/desktop_environment/policies/FlyScreenLockTimeoutHandler.h"

#include "modules/oss/desktop_environment/backends/BackendCommand.h"

#include <optional>

FlyScreenLockTimeoutHandler::FlyScreenLockTimeoutHandler(
    const UserSession& session,
    const SessionContext& context
)
    : backend(session, context)
{
}

bool FlyScreenLockTimeoutHandler::apply(int timeoutMinutes, std::string& error) const
{
    const int timeoutSeconds = timeoutMinutes * 60;
    if (!backend.setValue("ScreenSaver", "internal", error) ||
        !backend.setValue("ScreenSaverDBUS", "true", error) ||
        !backend.setValue("ScreenSaverDelay", std::to_string(timeoutSeconds), error)) {
        return false;
    }

    std::string screenSaver;
    std::string screenSaverDbus;
    std::string screenSaverDelay;
    if (!backend.getValue("ScreenSaver", screenSaver, error) ||
        !backend.getValue("ScreenSaverDBUS", screenSaverDbus, error) ||
        !backend.getValue("ScreenSaverDelay", screenSaverDelay, error)) {
        return false;
    }

    bool dbusEnabled = false;
    const std::optional<int> actualTimeout = desktop_backend::parseInteger(screenSaverDelay);
    if (screenSaver != "internal" ||
        !desktop_backend::parseBoolean(screenSaverDbus, dbusEnabled) ||
        !dbusEnabled ||
        !actualTimeout.has_value() || actualTimeout.value() != timeoutSeconds) {
        error = "FLY screen lock settings did not reach the requested state";
        return false;
    }
    return true;
}
