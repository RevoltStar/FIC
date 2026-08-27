#include "modules/oss/desktop_environment/policies/OSS_disable_kde_lock_screen_media_controls.h"

#include "modules/oss/desktop_environment/backends/BackendCommand.h"
#include "modules/oss/desktop_environment/backends/KdeBackend.h"
#include "modules/oss/desktop_environment/policies/KdeLockScreenMediaControlsApplicability.h"
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

OSS_disable_kde_lock_screen_media_controls::
OSS_disable_kde_lock_screen_media_controls(
    const fic::platform::PlatformExecutableResolver& executables)
    : DesktopEnvironment(),
      executables_(executables)
{
    this->policyName = "disable_kde_lock_screen_media_controls";
    this->policyTypeValue = std::make_unique<FixedPolicyTypeValue>();
}

bool OSS_disable_kde_lock_screen_media_controls::apply()
{
    std::vector<UserSession> sessions;
    std::string error;
    if (!SessionLocator::activeGraphicalSessions(
            executables_, sessions, error)) {
        this->log(
            "Failed to enumerate active graphical sessions: " + error,
            logLevel::ERROR);
        return false;
    }

    std::size_t applicableSessions = 0;
    const bool success =
        kde_lock_screen_media_controls::applyToKdeSessions(
            sessions,
            [](const UserSession& session,
               SessionContext& context,
               std::string& queryError) {
                return SessionAgentClient::query(
                    session, context, queryError);
            },
            [this](const UserSession& session,
                   const SessionContext& context) {
                return applyKdeSession(session, context);
            },
            applicableSessions);

    if (applicableSessions == 0) {
        this->log(
            "No active KDE graphical sessions; "
            "disable_kde_lock_screen_media_controls is not applicable",
            logLevel::DEBUG);
    }
    return success;
}

bool OSS_disable_kde_lock_screen_media_controls::applyKdeSession(
    const UserSession& session,
    const SessionContext& context)
{
    KdeBackend backend(session, context);
    std::string error;
    if (!backend.writeConfig(
            KSCREENLOCKER_CONFIG_FILE,
            KSCREENLOCKER_MEDIA_GROUPS,
            MEDIA_CONTROLS_KEY,
            "false",
            error)) {
        this->log(
            "Failed to disable KDE lock-screen media controls for user " +
                session.user + ", session " + session.id + ": " + error,
            logLevel::ERROR);
        return false;
    }

    std::string actualValue;
    if (!backend.readConfig(
            KSCREENLOCKER_CONFIG_FILE,
            KSCREENLOCKER_MEDIA_GROUPS,
            MEDIA_CONTROLS_KEY,
            actualValue,
            error)) {
        this->log(
            "Failed to verify KDE lock-screen media controls for user " +
                session.user + ", session " + session.id + ": " + error,
            logLevel::ERROR);
        return false;
    }

    bool mediaControlsEnabled = true;
    if (!desktop_backend::parseBoolean(
            actualValue, mediaControlsEnabled) || mediaControlsEnabled) {
        this->log(
            "KDE lock-screen media controls did not reach the requested "
            "disabled state for user " + session.user + ", session " +
                session.id,
            logLevel::ERROR);
        return false;
    }

    if (!backend.callDbusMethod(
            "org.kde.screensaver",
            "/ScreenSaver",
            "org.kde.screensaver",
            "configure",
            error)) {
        this->log(
            "Failed to reload KDE screen-lock settings for user " +
                session.user + ", session " + session.id + ": " + error,
            logLevel::ERROR);
        return false;
    }
    return true;
}
