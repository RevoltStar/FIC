#ifndef SCREEN_LOCK_TIMEOUT_HANDLER_H
#define SCREEN_LOCK_TIMEOUT_HANDLER_H

#include "session/UserSession.h"

#include <memory>
#include <string>

class ScreenLockTimeoutHandler {
public:
    virtual ~ScreenLockTimeoutHandler() = default;

    virtual const char* desktopName() const = 0;
    virtual bool apply(int timeoutMinutes, std::string& error) const = 0;
};

class ScreenLockTimeoutHandlerFactory {
public:
    static std::unique_ptr<ScreenLockTimeoutHandler> create(
        const UserSession& session,
        const SessionContext& context
    );
};

#endif // SCREEN_LOCK_TIMEOUT_HANDLER_H
