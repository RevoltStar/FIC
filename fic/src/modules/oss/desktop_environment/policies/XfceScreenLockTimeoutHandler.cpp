#include "modules/oss/desktop_environment/policies/XfceScreenLockTimeoutHandler.h"

XfceScreenLockTimeoutHandler::XfceScreenLockTimeoutHandler(
    const UserSession& session,
    const SessionContext& context
)
    : backend(session, context)
{
}

bool XfceScreenLockTimeoutHandler::apply(int timeoutMinutes, std::string& error) const
{
    return xfce_screen_lock_timeout::applyTimeout(
        backend, timeoutMinutes, error);
}
