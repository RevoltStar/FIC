#ifndef FLY_SCREEN_LOCK_TIMEOUT_HANDLER_H
#define FLY_SCREEN_LOCK_TIMEOUT_HANDLER_H

#include "modules/oss/desktop_environment/backends/FlyBackend.h"
#include "modules/oss/desktop_environment/policies/ScreenLockTimeoutHandler.h"

#include <string>

namespace fly_screen_lock_timeout {
template <typename Backend>
bool applyTimeout(const Backend& backend, int timeoutMinutes,
                  std::string& error)
{
    const std::string timeoutSeconds = std::to_string(timeoutMinutes * 60);
    return backend.setValue("ScreenSaver", "internal", error) &&
        backend.setValue("ScreenSaverDBUS", "true", error) &&
        backend.setValue("ScreenSaverDelay", timeoutSeconds, error);
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
