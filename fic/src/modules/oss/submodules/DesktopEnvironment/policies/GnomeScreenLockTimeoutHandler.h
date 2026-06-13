#ifndef GNOME_SCREEN_LOCK_TIMEOUT_HANDLER_H
#define GNOME_SCREEN_LOCK_TIMEOUT_HANDLER_H

#include "modules/oss/submodules/DesktopEnvironment/backends/GnomeBackend.h"
#include "modules/oss/submodules/DesktopEnvironment/policies/ScreenLockTimeoutHandler.h"

class GnomeScreenLockTimeoutHandler final : public ScreenLockTimeoutHandler {
public:
    GnomeScreenLockTimeoutHandler(const UserSession& session, const SessionContext& context);

    const char* desktopName() const override { return backend.name(); }
    bool apply(int timeoutMinutes, std::string& error) const override;

private:
    GnomeBackend backend;
};

#endif // GNOME_SCREEN_LOCK_TIMEOUT_HANDLER_H
