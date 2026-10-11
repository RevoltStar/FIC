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
// Runtime is read-only: the journaled system dconf state owns enforcement.
// Writing a user's overrides here would introduce separate unproven ownership.
template<typename Backend>
bool applyTimeout(const Backend& backend, int timeoutMinutes,
                  std::string& error) {
    const std::uint32_t expectedTimeoutSeconds =
        static_cast<std::uint32_t>(timeoutMinutes) * 60U;
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
    bool matches = false;
    if (!readState(matches, error)) return false;
    if (!matches) {
        error = "GNOME runtime does not reflect the protected system dconf state; user overrides were not changed";
        return false;
    }
    error.clear();
    return true;
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
