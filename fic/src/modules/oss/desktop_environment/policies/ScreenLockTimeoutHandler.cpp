#include "modules/oss/desktop_environment/policies/ScreenLockTimeoutHandler.h"

#include "modules/oss/desktop_environment/backends/DesktopEnvironmentBackend.h"
#include "modules/oss/desktop_environment/policies/FlyScreenLockTimeoutHandler.h"
#include "modules/oss/desktop_environment/policies/GnomeScreenLockTimeoutHandler.h"
#include "modules/oss/desktop_environment/policies/KdeScreenLockTimeoutHandler.h"
#include "modules/oss/desktop_environment/policies/XfceScreenLockTimeoutHandler.h"

std::unique_ptr<ScreenLockTimeoutHandler> ScreenLockTimeoutHandlerFactory::create(
    const UserSession& session,
    const SessionContext& context
)
{
    switch (DesktopEnvironmentBackend::kindFromName(context.desktop)) {
    case DesktopEnvironmentKind::Fly:
        return std::make_unique<FlyScreenLockTimeoutHandler>(session, context);
    case DesktopEnvironmentKind::Gnome:
        return std::make_unique<GnomeScreenLockTimeoutHandler>(session, context);
    case DesktopEnvironmentKind::Kde:
        return std::make_unique<KdeScreenLockTimeoutHandler>(session, context);
    case DesktopEnvironmentKind::Xfce:
        return std::make_unique<XfceScreenLockTimeoutHandler>(session, context);
    case DesktopEnvironmentKind::Unknown:
        return nullptr;
    }
    return nullptr;
}
