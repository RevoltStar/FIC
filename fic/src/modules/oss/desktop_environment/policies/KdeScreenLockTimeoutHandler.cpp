#include "modules/oss/desktop_environment/policies/KdeScreenLockTimeoutHandler.h"

KdeScreenLockTimeoutHandler::KdeScreenLockTimeoutHandler(
    const UserSession& session,
    const SessionContext& context,
    const KdeSessionTopologyInfo& sameUidKdeTopology
)
    : backend(session, context, sameUidKdeTopology)
{
}

bool KdeScreenLockTimeoutHandler::apply(int timeoutMinutes, std::string& error) const
{
    return kde_screen_lock_timeout::applyTimeout(
        backend, timeoutMinutes, error);
}
