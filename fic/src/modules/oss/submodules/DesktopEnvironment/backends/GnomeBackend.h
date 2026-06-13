#ifndef GNOME_BACKEND_H
#define GNOME_BACKEND_H

#include "modules/oss/submodules/DesktopEnvironment/backends/ScreenLockTimeoutBackend.h"

class GnomeBackend final : public ScreenLockTimeoutBackend {
public:
    const char* name() const override { return "GNOME"; }

    bool apply(
        const UserSession& session,
        const SessionContext& context,
        int timeoutMinutes,
        std::string& error
    ) const override;
};

#endif // GNOME_BACKEND_H
