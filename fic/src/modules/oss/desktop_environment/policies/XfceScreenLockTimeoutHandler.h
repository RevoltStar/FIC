#ifndef XFCE_SCREEN_LOCK_TIMEOUT_HANDLER_H
#define XFCE_SCREEN_LOCK_TIMEOUT_HANDLER_H

#include "modules/oss/desktop_environment/backends/XfceBackend.h"
#include "modules/oss/desktop_environment/policies/ScreenLockTimeoutHandler.h"

class XfceScreenLockTimeoutHandler final : public ScreenLockTimeoutHandler {
public:
    XfceScreenLockTimeoutHandler(const UserSession& session, const SessionContext& context);

    const char* desktopName() const override { return backend.name(); }
    bool apply(int timeoutMinutes, std::string& error) const override;

private:
    XfceBackend backend;
};

#endif // XFCE_SCREEN_LOCK_TIMEOUT_HANDLER_H
