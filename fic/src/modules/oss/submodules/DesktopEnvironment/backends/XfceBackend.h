#ifndef XFCE_BACKEND_H
#define XFCE_BACKEND_H

#include "modules/oss/submodules/DesktopEnvironment/backends/ScreenLockTimeoutBackend.h"

class XfceBackend final : public ScreenLockTimeoutBackend {
public:
    const char* name() const override { return "XFCE"; }

    bool apply(
        const UserSession& session,
        const SessionContext& context,
        int timeoutMinutes,
        std::string& error
    ) const override;
};

#endif // XFCE_BACKEND_H
