#include "modules/oss/desktop_environment/policies/KdeLockScreenMediaControlsApplicability.h"

#include "modules/oss/desktop_environment/backends/DesktopEnvironmentBackend.h"

namespace kde_lock_screen_media_controls {

bool applyToKdeSessions(const std::vector<UserSession>& sessions,
                        const ContextQuery& queryContext,
                        const SessionApply& applySession,
                        const ContextFailure& reportContextFailure,
                        std::size_t& applicableSessions)
{
    applicableSessions = 0;
    bool success = true;
    for (const UserSession& session : sessions) {
        SessionContext context;
        std::string error;
        if (!queryContext(session, context, error)) {
            reportContextFailure(session, error);
            success = false;
            continue;
        }
        const std::string desktop =
            DesktopEnvironmentBackend::normalizeName(context.desktop);
        if (desktop.empty() || desktop == "UNKNOWN") {
            reportContextFailure(
                session, "session agent did not provide a reliable desktop "
                    "identity");
            success = false;
            continue;
        }
        if (DesktopEnvironmentBackend::kindFromName(context.desktop) !=
            DesktopEnvironmentKind::Kde) {
            continue;
        }

        ++applicableSessions;
        if (!applySession(session, context)) {
            success = false;
        }
    }
    return success;
}

} // namespace kde_lock_screen_media_controls
