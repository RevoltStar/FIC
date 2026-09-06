#ifndef OSS_CONTROLLED_DESKTOP_ENVIRONMENTS_H
#define OSS_CONTROLLED_DESKTOP_ENVIRONMENTS_H

#include "modules/oss/desktop_environment/DesktopEnvironment.h"
#include "modules/oss/desktop_environment/DesktopEnvironmentControl.h"

class OSS_controlled_desktop_environments final
    : public DesktopEnvironment,
      public ControlledDesktopEnvironmentScope {
public:
    OSS_controlled_desktop_environments();

    bool apply() override;
    bool controlledDesktopEnvironments(
        DesktopEnvironmentSet& controlled,
        std::string& error) override;
};

#endif // OSS_CONTROLLED_DESKTOP_ENVIRONMENTS_H
