#ifndef KDE_SCREEN_LOCK_TIMEOUT_HANDLER_H
#define KDE_SCREEN_LOCK_TIMEOUT_HANDLER_H

#include "modules/oss/desktop_environment/backends/KdeBackend.h"
#include "modules/oss/desktop_environment/backends/BackendCommand.h"
#include "modules/oss/desktop_environment/policies/ScreenLockTimeoutHandler.h"

namespace kde_screen_lock_timeout {

template<typename Backend>
bool applyTimeout(const Backend& backend, int timeoutMinutes,
                  std::string& error) {
    constexpr const char* file = "kscreenlockerrc";
    constexpr const char* group = "Daemon";
    const auto readState = [&](bool& matches) {
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
        // Timeout трактуется как число с плавающей точкой ("5.0" и "5.00"
        // эквивалентны "5"); сам парсер не проверяет допустимый диапазон —
        // только корректность представления. Политику соответствия
        // определяет сравнение ниже.
        const auto actualTimeout = desktop_backend::parseStrictDouble(timeout);
        const auto grace = desktop_backend::parseStrictInteger(lockGrace);
        matches =
            desktop_backend::parseBoolean(autolock, autoEnabled) &&
            desktop_backend::parseBoolean(lock, lockEnabled) &&
            desktop_backend::parseBoolean(requirePassword, password) &&
            autoEnabled && lockEnabled && password &&
            actualTimeout &&
            *actualTimeout == static_cast<double>(timeoutMinutes) &&
            grace == 0;
        return true;
    };
    const auto writeState = [&]() {
        if (!backend.writeConfig(file, group, "Autolock", "true", error) ||
            !backend.writeConfig(file, group, "Timeout",
                                 std::to_string(timeoutMinutes), error) ||
            !backend.writeConfig(file, group, "Lock", "true", error) ||
            !backend.writeConfig(file, group, "LockGrace", "0", error) ||
            !backend.writeConfig(
                file, group, "RequirePassword", "true", error))
            return false;
        return true;
    };

    bool matches = false;
    if (!readState(matches)) return false;
    if (!matches && !writeState()) return false;

    if (!backend.callDbusMethod(
            "org.kde.screensaver", "/ScreenSaver",
            "org.kde.screensaver", "configure", error)) {
        error = "failed to reload KDE screen lock settings: " + error;
        return false;
    }

    matches = false;
    if (!readState(matches)) return false;
    if (!matches) {
        error = "KDE screen lock settings did not reach the requested state";
        return false;
    }
    if (!backend.validateRuntimeContext(error)) {
        error = "KDE screen locker changed during reconciliation: " + error;
        return false;
    }
    error.clear();
    return true;
}

} // namespace kde_screen_lock_timeout

class KdeScreenLockTimeoutHandler final : public ScreenLockTimeoutHandler {
public:
    KdeScreenLockTimeoutHandler(const UserSession& session,
                                const SessionContext& context,
                                const KdeSessionTopologyInfo& sameUidKdeTopology);

    const char* desktopName() const override { return backend.name(); }
    bool apply(int timeoutMinutes, std::string& error) const override;

private:
    KdeBackend backend;
};

#endif // KDE_SCREEN_LOCK_TIMEOUT_HANDLER_H
