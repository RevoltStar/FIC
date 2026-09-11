#include "modules/oss/desktop_environment/policies/FlyScreenLockTimeoutHandler.h"

FlyScreenLockTimeoutHandler::FlyScreenLockTimeoutHandler(
    const UserSession& session,
    const SessionContext& context
)
    : backend(session, context)
{
}

bool FlyScreenLockTimeoutHandler::apply(int timeoutMinutes, std::string& error) const
{
    return fly_screen_lock_timeout::applyTimeout(
        backend, timeoutMinutes, error);
}
