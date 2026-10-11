#ifndef FLY_SCREEN_LOCK_TIMEOUT_HANDLER_H
#define FLY_SCREEN_LOCK_TIMEOUT_HANDLER_H

#include "modules/oss/desktop_environment/backends/FlyBackend.h"
#include "modules/oss/desktop_environment/policies/ScreenLockTimeoutHandler.h"

#include <string>

namespace fly_screen_lock_timeout {
template <typename Backend>
bool applyTimeout(const Backend&, int,
                  std::string& error)
{
    // The available FLYWM_UPDATE_VAL call mutates session state without a
    // proven readback/conditional inverse. Persistent enforcement belongs to
    // the system backend; do not invent successful runtime convergence.
    error = "FLY runtime verification is unavailable; unjournaled FLYWM_UPDATE_VAL is refused";
    return false;
}
}

class FlyScreenLockTimeoutHandler final : public ScreenLockTimeoutHandler {
public:
    FlyScreenLockTimeoutHandler(const UserSession& session, const SessionContext& context);

    const char* desktopName() const override { return backend.name(); }
    bool apply(int timeoutMinutes, std::string& error) const override;

private:
    FlyBackend backend;
};

#endif // FLY_SCREEN_LOCK_TIMEOUT_HANDLER_H
