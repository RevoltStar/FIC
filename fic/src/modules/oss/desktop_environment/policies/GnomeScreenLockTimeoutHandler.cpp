#include "modules/oss/desktop_environment/policies/GnomeScreenLockTimeoutHandler.h"

#include <cstdint>

GnomeScreenLockTimeoutHandler::GnomeScreenLockTimeoutHandler(
    const UserSession& session,
    const SessionContext& context
)
    : backend(session, context)
{
}

bool GnomeScreenLockTimeoutHandler::apply(int timeoutMinutes, std::string& error) const
{
    return gnome_screen_lock_timeout::applyTimeout(backend, timeoutMinutes, error);
}
