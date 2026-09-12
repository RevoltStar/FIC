#ifndef OSS_DISABLE_KDE_LOCK_SCREEN_MEDIA_CONTROLS_H
#define OSS_DISABLE_KDE_LOCK_SCREEN_MEDIA_CONTROLS_H

#include "modules/oss/desktop_environment/SessionAwareDesktopEnvironmentPolicy.h"
#include "modules/oss/desktop_environment/backends/BackendCommand.h"
#include "session/UserSession.h"

#include <string>
#include <vector>

namespace kde_media_controls {

constexpr const char* KSCREENLOCKER_CONFIG_FILE = "kscreenlockerrc";
constexpr const char* MEDIA_CONTROLS_KEY = "showMediaControls";
constexpr const char* MEDIA_CONTROLS_DISABLED_VALUE = "false";

inline const std::vector<std::string> KSCREENLOCKER_MEDIA_GROUPS{
    "Greeter",
    "LnF",
    "General"
};

// Reconciliation protocol KDE lock-screen media controls:
// read → write only if mismatch → ALWAYS org.kde.screensaver.configure
// → final readback → validateRuntimeContext.
//
// Уже корректный KConfig на диске НЕ доказывает, что running KScreenLocker
// перечитал файл: cached runtime state может остаться stale. Поэтому
// configure вызывается ровно один раз на каждую попытку reconciliation
// независимо от initial file match; write остаётся conditional
// (minimally mutating): если файл уже false, повторно он не пишется.
//
// Ограничение best-available contract: отдельного runtime getter для
// showMediaControls у KScreenLocker нет, поэтому успешный configure +
// final KConfig readback + стабильный captured KScreenLocker identity —
// максимально доступное доказательство конвергенции (тот же принцип, что
// и для KDE screenlock timeout). Более сильную runtime guarantee это не
// доказывает.
template<typename Backend>
bool reconcileMediaControls(const Backend& backend, std::string& error) {
    const auto readState = [&](bool& matches) {
        std::string actualValue;
        if (!backend.readConfig(
                KSCREENLOCKER_CONFIG_FILE, KSCREENLOCKER_MEDIA_GROUPS,
                MEDIA_CONTROLS_KEY, actualValue, error))
            return false;
        bool enabled = true;
        matches = desktop_backend::parseBoolean(actualValue, enabled) &&
                  !enabled;
        return true;
    };

    bool matches = false;
    if (!readState(matches))
        return false;

    if (!matches &&
        !backend.writeConfig(
            KSCREENLOCKER_CONFIG_FILE,
            KSCREENLOCKER_MEDIA_GROUPS,
            MEDIA_CONTROLS_KEY,
            MEDIA_CONTROLS_DISABLED_VALUE,
            error)) {
        return false;
    }

    if (!backend.callDbusMethod(
            "org.kde.screensaver",
            "/ScreenSaver",
            "org.kde.screensaver",
            "configure",
            error)) {
        error = "failed to reload KDE lock-screen media-control settings: " +
                error;
        return false;
    }

    matches = false;
    if (!readState(matches))
        return false;

    if (!matches) {
        error =
            "KDE lock-screen media controls did not reach the requested state";
        return false;
    }

    if (!backend.validateRuntimeContext(error)) {
        error = "KDE screen locker changed during reconciliation: " + error;
        return false;
    }

    error.clear();
    return true;
}

} // namespace kde_media_controls

class OSS_disable_kde_lock_screen_media_controls final
    : public SessionAwareDesktopEnvironmentPolicy
{
public:
    explicit OSS_disable_kde_lock_screen_media_controls(
        ControlledDesktopEnvironmentScope& scope,
        std::shared_ptr<GraphicalSessionInventory> inventory);

protected:
    bool prepare(std::string& error) override;
    bool relevantTo(DesktopEnvironmentKind desktop) const override;
    EnforcementMode modeFor(DesktopEnvironmentKind desktop) const override;
    bool reconcileControlledSession(
        const SessionReconcileContext& context,
        std::string& error) override;
};

#endif // OSS_DISABLE_KDE_LOCK_SCREEN_MEDIA_CONTROLS_H
