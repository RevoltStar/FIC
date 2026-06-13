#include "modules/oss/submodules/DesktopEnvironment/backends/GnomeBackend.h"

#include "modules/oss/submodules/DesktopEnvironment/backends/BackendCommand.h"

#include <optional>

bool GnomeBackend::apply(
    const UserSession& session,
    const SessionContext& context,
    int timeoutMinutes,
    std::string& error
) const {
    const std::string gsettings = desktop_backend::findExecutable({
        "/usr/bin/gsettings",
        "/bin/gsettings"
    });
    if (gsettings.empty()) {
        error = "gsettings was not found";
        return false;
    }

    ProcessResult result;
    const std::string timeoutSeconds = "uint32 " + std::to_string(timeoutMinutes * 60);
    if (!desktop_backend::execute(session, context, gsettings,
                                  {"set", "org.gnome.desktop.session", "idle-delay", timeoutSeconds},
                                  result, error) ||
        !desktop_backend::execute(session, context, gsettings,
                                  {"set", "org.gnome.desktop.screensaver", "lock-enabled", "true"},
                                  result, error) ||
        !desktop_backend::execute(session, context, gsettings,
                                  {"set", "org.gnome.desktop.screensaver", "lock-delay", "uint32 0"},
                                  result, error)) {
        return false;
    }

    ProcessResult idleDelay;
    ProcessResult lockEnabled;
    ProcessResult lockDelay;
    if (!desktop_backend::execute(session, context, gsettings,
                                  {"get", "org.gnome.desktop.session", "idle-delay"},
                                  idleDelay, error) ||
        !desktop_backend::execute(session, context, gsettings,
                                  {"get", "org.gnome.desktop.screensaver", "lock-enabled"},
                                  lockEnabled, error) ||
        !desktop_backend::execute(session, context, gsettings,
                                  {"get", "org.gnome.desktop.screensaver", "lock-delay"},
                                  lockDelay, error)) {
        return false;
    }

    const std::optional<int> actualIdleDelay = desktop_backend::parseInteger(idleDelay.standardOutput);
    const std::optional<int> actualLockDelay = desktop_backend::parseInteger(lockDelay.standardOutput);
    bool actualLockEnabled = false;
    if (!actualIdleDelay.has_value() || actualIdleDelay.value() != timeoutMinutes * 60 ||
        !actualLockDelay.has_value() || actualLockDelay.value() != 0 ||
        !desktop_backend::parseBoolean(lockEnabled.standardOutput, actualLockEnabled) ||
        !actualLockEnabled) {
        error = "GNOME screen lock settings did not reach the requested state";
        return false;
    }
    return true;
}
