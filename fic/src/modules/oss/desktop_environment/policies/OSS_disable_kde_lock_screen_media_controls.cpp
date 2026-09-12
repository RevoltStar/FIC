#include "modules/oss/desktop_environment/policies/OSS_disable_kde_lock_screen_media_controls.h"

#include "modules/oss/desktop_environment/KdeSessionTopology.h"
#include "modules/oss/desktop_environment/backends/BackendCommand.h"
#include "modules/oss/desktop_environment/backends/KdeBackend.h"
#include <string>
#include <utility>
#include <vector>

namespace {

const std::vector<std::string> KSCREENLOCKER_MEDIA_GROUPS{
    "Greeter",
    "LnF",
    "General"
};

constexpr const char* KSCREENLOCKER_CONFIG_FILE = "kscreenlockerrc";
constexpr const char* MEDIA_CONTROLS_KEY = "showMediaControls";

} // namespace

OSS_disable_kde_lock_screen_media_controls::
OSS_disable_kde_lock_screen_media_controls(
    ControlledDesktopEnvironmentScope& scope,
    std::shared_ptr<GraphicalSessionInventory> inventory)
    : SessionAwareDesktopEnvironmentPolicy(scope, std::move(inventory))
{
    this->policyName = "disable_kde_lock_screen_media_controls";
    this->policyTypeValue = std::make_unique<FixedPolicyTypeValue>();
}

bool OSS_disable_kde_lock_screen_media_controls::prepare(std::string& error)
{
    error.clear();
    return true;
}

bool OSS_disable_kde_lock_screen_media_controls::relevantTo(
    DesktopEnvironmentKind desktop) const
{
    return desktop == DesktopEnvironmentKind::Kde;
}

EnforcementMode OSS_disable_kde_lock_screen_media_controls::modeFor(
    DesktopEnvironmentKind desktop) const
{
    return desktop == DesktopEnvironmentKind::Kde
        ? EnforcementMode::SessionOnly
        : EnforcementMode::Unsupported;
}

bool OSS_disable_kde_lock_screen_media_controls::reconcileControlledSession(
    const SessionReconcileContext& context,
    std::string& error)
{
    const KdeSessionTopologyInfo topology = determineKdeSessionTopology(
        context.target, context.sessions, context.inventoryComplete);
    KdeBackend backend(context.target.session, context.target.context,
                       topology);
    const auto readState = [&](bool& matches, std::string&) {
        std::string actualValue;
        if (!backend.readConfig(
                KSCREENLOCKER_CONFIG_FILE, KSCREENLOCKER_MEDIA_GROUPS,
                MEDIA_CONTROLS_KEY, actualValue, error)) return false;
        bool enabled = true;
        matches = desktop_backend::parseBoolean(actualValue, enabled) && !enabled;
        return true;
    };
    const auto writeState = [&](std::string&) {
        if (!backend.writeConfig(
            KSCREENLOCKER_CONFIG_FILE,
            KSCREENLOCKER_MEDIA_GROUPS,
            MEDIA_CONTROLS_KEY,
            "false",
            error)) {
            return false;
        }
        return backend.callDbusMethod(
            "org.kde.screensaver",
            "/ScreenSaver",
            "org.kde.screensaver",
            "configure",
            error);
    };
    bool matches = false;
    if (!readState(matches, error)) return false;
    if (!matches) {
        if (!writeState(error) || !readState(matches, error)) return false;
        if (!matches) {
            error = "KDE lock-screen media controls did not reach the requested state";
            return false;
        }
    }
    if (!backend.validateRuntimeContext(error)) {
        error = "KDE screen locker changed during reconciliation: " + error;
        return false;
    }
    error.clear();
    return true;
}
