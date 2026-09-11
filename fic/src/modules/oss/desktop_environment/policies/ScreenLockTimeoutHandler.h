#ifndef SCREEN_LOCK_TIMEOUT_HANDLER_H
#define SCREEN_LOCK_TIMEOUT_HANDLER_H

#include <memory>
#include <string>

struct ClassifiedGraphicalSession;

class ScreenLockTimeoutHandler {
public:
    virtual ~ScreenLockTimeoutHandler() = default;

    virtual const char* desktopName() const = 0;
    virtual bool apply(int timeoutMinutes, std::string& error) const = 0;
};

// canonical desktop identity — только ClassifiedGraphicalSession.desktop;
// factory не выполняет повторную классификацию context.desktop.
class ScreenLockTimeoutHandlerFactory {
public:
    static std::unique_ptr<ScreenLockTimeoutHandler> create(
        const ClassifiedGraphicalSession& session
    );
};

#endif // SCREEN_LOCK_TIMEOUT_HANDLER_H
