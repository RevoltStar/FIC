#ifndef OSS_DISABLE_KDE_LOCK_SCREEN_MEDIA_CONTROLS_H
#define OSS_DISABLE_KDE_LOCK_SCREEN_MEDIA_CONTROLS_H

#include "modules/oss/desktop_environment/DesktopEnvironment.h"
#include "platform/PlatformExecutableResolver.h"
#include "session/UserSession.h"

class OSS_disable_kde_lock_screen_media_controls final
    : public DesktopEnvironment
{
public:
    explicit OSS_disable_kde_lock_screen_media_controls(
        const fic::platform::PlatformExecutableResolver& executables);

    bool apply() override;

private:
    bool applyKdeSession(const UserSession& session,
                         const SessionContext& context);

    const fic::platform::PlatformExecutableResolver& executables_;
};

#endif // OSS_DISABLE_KDE_LOCK_SCREEN_MEDIA_CONTROLS_H
