#ifndef SCREEN_LOCK_TIMEOUT_HANDLER_H
#define SCREEN_LOCK_TIMEOUT_HANDLER_H

#include <memory>
#include <string>

struct SessionReconcileContext;

class ScreenLockTimeoutHandler {
public:
    virtual ~ScreenLockTimeoutHandler() = default;

    virtual const char* desktopName() const = 0;
    virtual bool apply(int timeoutMinutes, std::string& error) const = 0;
};

// canonical desktop identity — только SessionReconcileContext.target.desktop
// (т.е. ClassifiedGraphicalSession.desktop); factory не выполняет повторную
// классификацию context.desktop и не вычисляет topology для non-KDE
// handlers.
class ScreenLockTimeoutHandlerFactory {
public:
    static std::unique_ptr<ScreenLockTimeoutHandler> create(
        const SessionReconcileContext& context
    );
};

#endif // SCREEN_LOCK_TIMEOUT_HANDLER_H
