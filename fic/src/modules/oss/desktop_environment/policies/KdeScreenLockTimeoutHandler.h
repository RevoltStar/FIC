#ifndef KDE_SCREEN_LOCK_TIMEOUT_HANDLER_H
#define KDE_SCREEN_LOCK_TIMEOUT_HANDLER_H

#include "modules/oss/desktop_environment/backends/KdeBackend.h"
#include "modules/oss/desktop_environment/backends/BackendCommand.h"
#include "modules/oss/desktop_environment/SessionSettingReconciler.h"
#include "modules/oss/desktop_environment/policies/ScreenLockTimeoutHandler.h"

namespace kde_screen_lock_timeout {

template<typename Backend>
bool applyTimeout(const Backend& backend, int timeoutMinutes,
                  std::string& error) {
    constexpr const char* file = "kscreenlockerrc";
    constexpr const char* group = "Daemon";
    const auto readState = [&](bool& matches, std::string&) {
        std::string autolock;
        std::string timeout;
        std::string lock;
        std::string lockGrace;
        std::string requirePassword;
        if (!backend.readConfig(file, group, "Autolock", autolock, error) ||
            !backend.readConfig(file, group, "Timeout", timeout, error) ||
            !backend.readConfig(file, group, "Lock", lock, error) ||
            !backend.readConfig(file, group, "LockGrace", lockGrace, error))
            return false;
        if (!backend.readConfig(
                file, group, "RequirePassword", requirePassword, error))
            return false;
        bool autoEnabled = false;
        bool lockEnabled = false;
        bool password = false;
        const auto actualTimeout = desktop_backend::parseInteger(timeout);
        const auto grace = desktop_backend::parseInteger(lockGrace);
        matches =
            desktop_backend::parseBoolean(autolock, autoEnabled) &&
            desktop_backend::parseBoolean(lock, lockEnabled) &&
            desktop_backend::parseBoolean(requirePassword, password) &&
            autoEnabled && lockEnabled && password &&
            actualTimeout == timeoutMinutes && grace == 0;
        return true;
    };
    const auto writeState = [&](std::string&) {
        if (!backend.writeConfig(file, group, "Autolock", "true", error) ||
            !backend.writeConfig(file, group, "Timeout",
                                 std::to_string(timeoutMinutes), error) ||
            !backend.writeConfig(file, group, "Lock", "true", error) ||
            !backend.writeConfig(file, group, "LockGrace", "0", error) ||
            !backend.writeConfig(
                file, group, "RequirePassword", "true", error))
            return false;
        if (!backend.callDbusMethod(
                "org.kde.screensaver", "/ScreenSaver",
                "org.kde.screensaver", "configure", error)) {
            error = "failed to reload KDE screen lock settings: " + error;
            return false;
        }
        return true;
    };
    return desktop_policy::reconcileEffectiveSetting(
        readState, writeState,
        "KDE screen lock settings did not reach the requested state", error);
}

} // namespace kde_screen_lock_timeout

class KdeScreenLockTimeoutHandler final : public ScreenLockTimeoutHandler {
public:
    KdeScreenLockTimeoutHandler(const UserSession& session, const SessionContext& context);

    const char* desktopName() const override { return backend.name(); }
    bool apply(int timeoutMinutes, std::string& error) const override;

private:
    KdeBackend backend;
};

#endif // KDE_SCREEN_LOCK_TIMEOUT_HANDLER_H
