#include "modules/oss/submodules/DesktopEnvironment/policies/ScreenLockTimeoutHandler.h"

#include "modules/oss/submodules/DesktopEnvironment/backends/DesktopEnvironmentBackend.h"
#include "modules/oss/submodules/DesktopEnvironment/policies/GnomeScreenLockTimeoutHandler.h"
#include "modules/oss/submodules/DesktopEnvironment/policies/KdeScreenLockTimeoutHandler.h"
#include "modules/oss/submodules/DesktopEnvironment/policies/XfceScreenLockTimeoutHandler.h"

std::unique_ptr<ScreenLockTimeoutHandler> ScreenLockTimeoutHandlerFactory::create(
    const UserSession& session,
    const SessionContext& context
)
{
    switch (DesktopEnvironmentBackend::kindFromName(context.desktop)) {
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
