#ifndef SCREEN_LOCK_TIMEOUT_BACKEND_H
#define SCREEN_LOCK_TIMEOUT_BACKEND_H

#include "session/UserSession.h"

#include <memory>
#include <string>

class ScreenLockTimeoutBackend {
public:
    virtual ~ScreenLockTimeoutBackend() = default;

    virtual const char* name() const = 0;

    virtual bool apply(
        const UserSession& session,
        const SessionContext& context,
        int timeoutMinutes,
        std::string& error
    ) const = 0;
};

class ScreenLockTimeoutBackendFactory {
public:
    static std::unique_ptr<ScreenLockTimeoutBackend> create(const std::string& desktop);
    static std::string normalizeDesktopName(std::string desktop);
};

#endif // SCREEN_LOCK_TIMEOUT_BACKEND_H
