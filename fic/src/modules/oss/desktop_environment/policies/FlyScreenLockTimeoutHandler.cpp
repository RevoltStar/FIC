#include "modules/oss/desktop_environment/policies/FlyScreenLockTimeoutHandler.h"

#include "modules/oss/desktop_environment/backends/BackendCommand.h"
#include "modules/oss/desktop_environment/SessionSettingReconciler.h"

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
    const auto readState = [&](bool& matches, std::string&) {
        std::string screenSaver, screenSaverDbus, screenSaverDelay;
        if (!backend.getValue("ScreenSaver", screenSaver, error) ||
            !backend.getValue("ScreenSaverDBUS", screenSaverDbus, error) ||
            !backend.getValue("ScreenSaverDelay", screenSaverDelay, error)) return false;
        bool dbusEnabled = false;
        const auto actualTimeout = desktop_backend::parseInteger(screenSaverDelay);
        matches = screenSaver == "internal" &&
            desktop_backend::parseBoolean(screenSaverDbus, dbusEnabled) &&
            dbusEnabled && actualTimeout.has_value() &&
            actualTimeout.value() == timeoutSeconds;
        return true;
    };
    const auto writeState = [&](std::string&) {
        return backend.setValue("ScreenSaver", "internal", error) &&
            backend.setValue("ScreenSaverDBUS", "true", error) &&
            backend.setValue("ScreenSaverDelay", std::to_string(timeoutSeconds), error);
    };
    return desktop_policy::reconcileEffectiveSetting(
        readState, writeState,
        "FLY screen lock settings did not reach the requested state", error);
}
