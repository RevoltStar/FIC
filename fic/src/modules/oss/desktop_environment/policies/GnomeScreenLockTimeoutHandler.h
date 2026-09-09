#ifndef GNOME_SCREEN_LOCK_TIMEOUT_HANDLER_H
#define GNOME_SCREEN_LOCK_TIMEOUT_HANDLER_H

#include "modules/oss/desktop_environment/backends/GnomeBackend.h"
#include "modules/oss/desktop_environment/backends/BackendCommand.h"
#include "modules/oss/desktop_environment/SessionSettingReconciler.h"
#include "modules/oss/desktop_environment/policies/ScreenLockTimeoutHandler.h"

#include <cstdint>
#include <string>

namespace gnome_screen_lock_timeout {

// Требуемое состояние GNOME screen lock: idle-delay == N*60, lock-enabled ==
// true, lock-delay == 0 и disable-lock-screen == false. Последний ключ обязателен:
// org.gnome.desktop.lockdown disable-lock-screen=true не даёт GNOME Shell
// заблокировать экран, поэтому state matching учитывает все четыре значения.
// Логика — шаблон над бэкендом с интерфейсом GnomeBackend, чтобы текущая-сессия
// convergence был проверяем без живой графической сессии.
template<typename Backend>
bool applyTimeout(const Backend& backend, int timeoutMinutes,
                  std::string& error) {
    const std::uint32_t expectedTimeoutSeconds =
        static_cast<std::uint32_t>(timeoutMinutes) * 60U;
    const std::string timeoutSeconds =
        "uint32 " + std::to_string(expectedTimeoutSeconds);
    const auto readState = [&](bool& matches, std::string&) {
        std::uint32_t idleDelay = 0, lockDelay = 0;
        std::string lockEnabled, disableLockScreen;
        if (!backend.getUInt32Setting("org.gnome.desktop.session", "idle-delay", idleDelay, error) ||
            !backend.getSetting("org.gnome.desktop.screensaver", "lock-enabled", lockEnabled, error) ||
            !backend.getUInt32Setting("org.gnome.desktop.screensaver", "lock-delay", lockDelay, error) ||
            !backend.getSetting("org.gnome.desktop.lockdown", "disable-lock-screen", disableLockScreen, error)) return false;
        bool enabled = false, lockScreenDisabled = true;
        matches = desktop_backend::parseBoolean(lockEnabled, enabled) && enabled &&
            desktop_backend::parseBoolean(disableLockScreen, lockScreenDisabled) &&
            !lockScreenDisabled &&
            idleDelay == expectedTimeoutSeconds && lockDelay == 0U;
        return true;
    };
    const auto writeState = [&](std::string&) {
        return backend.setSetting("org.gnome.desktop.session", "idle-delay", timeoutSeconds, error) &&
            backend.setSetting("org.gnome.desktop.screensaver", "lock-enabled", "true", error) &&
            backend.setSetting("org.gnome.desktop.screensaver", "lock-delay", "uint32 0", error) &&
            backend.setSetting("org.gnome.desktop.lockdown", "disable-lock-screen", "false", error);
    };
    return desktop_policy::reconcileEffectiveSetting(
        readState, writeState,
        "GNOME screen lock settings did not reach the requested state", error);
}

} // namespace gnome_screen_lock_timeout

class GnomeScreenLockTimeoutHandler final : public ScreenLockTimeoutHandler {
public:
    GnomeScreenLockTimeoutHandler(const UserSession& session, const SessionContext& context);

    const char* desktopName() const override { return backend.name(); }
    bool apply(int timeoutMinutes, std::string& error) const override;

private:
    GnomeBackend backend;
};

#endif // GNOME_SCREEN_LOCK_TIMEOUT_HANDLER_H
