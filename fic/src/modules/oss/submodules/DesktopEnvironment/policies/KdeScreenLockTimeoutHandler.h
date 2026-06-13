#ifndef KDE_SCREEN_LOCK_TIMEOUT_HANDLER_H
#define KDE_SCREEN_LOCK_TIMEOUT_HANDLER_H

#include "modules/oss/submodules/DesktopEnvironment/backends/KdeBackend.h"
#include "modules/oss/submodules/DesktopEnvironment/policies/ScreenLockTimeoutHandler.h"

class KdeScreenLockTimeoutHandler final : public ScreenLockTimeoutHandler {
public:
    KdeScreenLockTimeoutHandler(const UserSession& session, const SessionContext& context);

    const char* desktopName() const override { return backend.name(); }
    bool apply(int timeoutMinutes, std::string& error) const override;

private:
    KdeBackend backend;
};

#endif // KDE_SCREEN_LOCK_TIMEOUT_HANDLER_H
