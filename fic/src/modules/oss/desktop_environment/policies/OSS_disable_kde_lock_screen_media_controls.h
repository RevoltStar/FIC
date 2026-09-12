#ifndef OSS_DISABLE_KDE_LOCK_SCREEN_MEDIA_CONTROLS_H
#define OSS_DISABLE_KDE_LOCK_SCREEN_MEDIA_CONTROLS_H

#include "modules/oss/desktop_environment/SessionAwareDesktopEnvironmentPolicy.h"
#include "session/UserSession.h"

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
