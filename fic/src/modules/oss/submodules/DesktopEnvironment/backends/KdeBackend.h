#ifndef KDE_BACKEND_H
#define KDE_BACKEND_H

#include "modules/oss/submodules/DesktopEnvironment/backends/ScreenLockTimeoutBackend.h"

class KdeBackend final : public ScreenLockTimeoutBackend {
public:
    const char* name() const override { return "KDE Plasma"; }

    bool apply(
        const UserSession& session,
        const SessionContext& context,
        int timeoutMinutes,
        std::string& error
    ) const override;
};

#endif // KDE_BACKEND_H
