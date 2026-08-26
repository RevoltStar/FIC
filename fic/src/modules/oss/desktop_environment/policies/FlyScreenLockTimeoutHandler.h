#ifndef FLY_SCREEN_LOCK_TIMEOUT_HANDLER_H
#define FLY_SCREEN_LOCK_TIMEOUT_HANDLER_H

#include "modules/oss/desktop_environment/backends/FlyBackend.h"
#include "modules/oss/desktop_environment/policies/ScreenLockTimeoutHandler.h"

class FlyScreenLockTimeoutHandler final : public ScreenLockTimeoutHandler {
public:
    FlyScreenLockTimeoutHandler(const UserSession& session, const SessionContext& context);

    const char* desktopName() const override { return backend.name(); }
    bool apply(int timeoutMinutes, std::string& error) const override;

private:
    FlyBackend backend;
};

#endif // FLY_SCREEN_LOCK_TIMEOUT_HANDLER_H
