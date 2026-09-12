#include "modules/oss/desktop_environment/policies/ScreenLockTimeoutHandler.h"

#include "modules/oss/desktop_environment/DesktopEnvironmentControl.h"
#include "modules/oss/desktop_environment/backends/DesktopEnvironmentBackend.h"
#include "modules/oss/desktop_environment/policies/FlyScreenLockTimeoutHandler.h"
#include "modules/oss/desktop_environment/policies/GnomeScreenLockTimeoutHandler.h"
#include "modules/oss/desktop_environment/policies/KdeScreenLockTimeoutHandler.h"
#include "modules/oss/desktop_environment/policies/XfceScreenLockTimeoutHandler.h"

std::unique_ptr<ScreenLockTimeoutHandler> ScreenLockTimeoutHandlerFactory::create(
    const SessionReconcileContext& context
)
{
    switch (context.target.desktop) {
    case DesktopEnvironmentKind::Fly:
        return std::make_unique<FlyScreenLockTimeoutHandler>(
            context.target.session, context.target.context);
    case DesktopEnvironmentKind::Gnome:
        return std::make_unique<GnomeScreenLockTimeoutHandler>(
            context.target.session, context.target.context);
    case DesktopEnvironmentKind::Kde: {
        const KdeSessionTopologyInfo topology = determineKdeSessionTopology(
            context.target, context.sessions, context.inventoryComplete);
        return std::make_unique<KdeScreenLockTimeoutHandler>(
            context.target.session, context.target.context, topology);
    }
    case DesktopEnvironmentKind::Xfce:
        return std::make_unique<XfceScreenLockTimeoutHandler>(
            context.target.session, context.target.context);
    case DesktopEnvironmentKind::Lxqt:
    case DesktopEnvironmentKind::Unknown:
        return nullptr;
    }
    return nullptr;
}
