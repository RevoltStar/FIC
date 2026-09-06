#ifndef FIC_SYSTEM_GRAPHICAL_SESSION_INVENTORY_H
#define FIC_SYSTEM_GRAPHICAL_SESSION_INVENTORY_H

#include "modules/oss/desktop_environment/DesktopEnvironmentControl.h"
#include "platform/PlatformExecutableResolver.h"

class SystemGraphicalSessionInventory final : public GraphicalSessionInventory {
public:
    explicit SystemGraphicalSessionInventory(
        const fic::platform::PlatformExecutableResolver& executables);

    bool currentSessions(
        std::vector<ClassifiedGraphicalSession>& sessions,
        std::string& error) override;

private:
    const fic::platform::PlatformExecutableResolver& executables_;
};

#endif // FIC_SYSTEM_GRAPHICAL_SESSION_INVENTORY_H
