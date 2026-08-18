#include "modules/oss/submodules/DesktopEnvironment/OSS_disable_videodisplay_when_locked.h"

#include "modules/oss/submodules/DesktopEnvironment/backends/BackendCommand.h"
#include "modules/oss/submodules/DesktopEnvironment/backends/DesktopEnvironmentBackend.h"
#include "modules/oss/submodules/DesktopEnvironment/backends/KdeBackend.h"
#include "session/SessionAgentClient.h"
#include "session/SessionLocator.h"

#include <string>
#include <vector>

namespace {

const std::vector<std::string> KSCREENLOCKER_MEDIA_GROUPS{
    "Greeter",
    "LnF",
    "General"
};

constexpr const char* KSCREENLOCKER_CONFIG_FILE = "kscreenlockerrc";
constexpr const char* MEDIA_CONTROLS_KEY = "showMediaControls";

} // namespace

OSS_disable_videodisplay_when_locked::
OSS_disable_videodisplay_when_locked(
    const fic::platform::PlatformExecutableResolver& executables)
    : DesktopEnvironment(),
      executables_(executables)
{
    this->policyName = "disable_videodisplay_when_locked";
    this->policyTypeValue = std::make_unique<FixedPolicyTypeValue>();
}

bool OSS_disable_videodisplay_when_locked::apply()
{
    std::vector<UserSession> sessions;
    std::string error;

    if (!SessionLocator::activeGraphicalSessions(
            executables_, sessions, error)) {
        this->log(
            "Failed to enumerate graphical sessions: " + error,
            logLevel::ERROR
        );
        return false;
    }

    if (sessions.empty()) {
        this->log(
            "No active graphical sessions; "
            "disable_videodisplay_when_locked is not applicable",
            logLevel::DEBUG
        );
        return true;
    }

    bool success = true;

    for (const UserSession& session : sessions) {
        SessionContext context;

        if (!SessionAgentClient::query(session, context, error)) {
            this->log(
                "Session agent is unavailable for user " +
                session.user +
                ", session " +
                session.id +
                ": " +
                error,
                logLevel::ERROR
            );
            success = false;
            continue;
        }

        if (DesktopEnvironmentBackend::kindFromName(context.desktop) !=
            DesktopEnvironmentKind::Kde) {
            const std::string desktop =
                DesktopEnvironmentBackend::normalizeName(context.desktop);

            this->log(
                "disable_videodisplay_when_locked is not supported "
                "for desktop " +
                (desktop.empty()
                    ? std::string("UNKNOWN")
                    : desktop) +
                ", user " +
                session.user +
                ", session " +
                session.id,
                logLevel::ERROR
            );
            success = false;
            continue;
        }

        KdeBackend backend(session, context);

        std::string handlerError;
        if (!backend.writeConfig(
                KSCREENLOCKER_CONFIG_FILE,
                KSCREENLOCKER_MEDIA_GROUPS,
                MEDIA_CONTROLS_KEY,
                "false",
                handlerError)) {
            this->log(
                "Failed to disable KDE lock-screen media controls "
                "for user " +
                session.user +
                ", session " +
                session.id +
                ": " +
                handlerError,
                logLevel::ERROR
            );
            success = false;
            continue;
        }

        std::string actualValue;
        if (!backend.readConfig(
                KSCREENLOCKER_CONFIG_FILE,
                KSCREENLOCKER_MEDIA_GROUPS,
                MEDIA_CONTROLS_KEY,
                actualValue,
                handlerError)) {
            this->log(
                "Failed to verify KDE lock-screen media controls "
                "for user " +
                session.user +
                ", session " +
                session.id +
                ": " +
                handlerError,
                logLevel::ERROR
            );
            success = false;
            continue;
        }

        bool mediaControlsEnabled = true;
        if (!desktop_backend::parseBoolean(
                actualValue,
                mediaControlsEnabled) ||
            mediaControlsEnabled) {
            this->log(
                "KDE lock-screen media controls did not reach "
                "the requested disabled state for user " +
                session.user +
                ", session " +
                session.id,
                logLevel::ERROR
            );
            success = false;
            continue;
        }

        if (!backend.callDbusMethod(
                "org.kde.screensaver",
                "/ScreenSaver",
                "org.kde.screensaver",
                "configure",
                handlerError)) {
            this->log(
                "Failed to reload KDE screen-lock settings "
                "for user " +
                session.user +
                ", session " +
                session.id +
                ": " +
                handlerError,
                logLevel::ERROR
            );
            success = false;
        }
    }

    return success;
}