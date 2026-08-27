#include "modules/oss/desktop_environment/policies/KdeLockScreenMediaControlsApplicability.h"

#include "modules/oss/desktop_environment/backends/DesktopEnvironmentBackend.h"

namespace kde_lock_screen_media_controls {

ApplicabilityResult applyToKdeSessions(
    const std::vector<UserSession>& sessions,
    const ContextQuery& queryContext,
    const SessionApply& applySession,
    const ContextFailure& reportContextFailure)
{
    ApplicabilityResult result;
    for (const UserSession& session : sessions) {
        SessionContext context;
        std::string error;
        if (!queryContext(session, context, error)) {
            reportContextFailure(session, error);
            result.success = false;
            ++result.classificationFailures;
            continue;
        }
        const DesktopEnvironmentKind kind =
            DesktopEnvironmentBackend::kindFromName(context.desktop);
        if (context.desktop.empty() || kind == DesktopEnvironmentKind::Unknown) {
            reportContextFailure(
                session, "session agent did not provide a reliable desktop "
                    "identity");
            result.success = false;
            ++result.classificationFailures;
            continue;
        }
        if (kind != DesktopEnvironmentKind::Kde) {
            continue;
        }

        ++result.applicableSessions;
        if (!applySession(session, context)) {
            result.success = false;
        }
    }
    return result;
}

} // namespace kde_lock_screen_media_controls
