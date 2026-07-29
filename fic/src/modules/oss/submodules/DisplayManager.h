#ifndef DISPLAYMANAGER_H
#define DISPLAYMANAGER_H

#include "modules/oss/OSS.h"
#include "platform/PlatformProfile.h"

#include <string>
#include <vector>

class DisplayManager : public OSS
{
protected:
    std::string detectDisplayManager() const;
    const fic::platform::DisplayManagerPlatformConfig& displayManagerConfig() const;
public:
    DisplayManager(
        fic::platform::SystemToolsPlatformConfig systemTools,
        fic::platform::DisplayManagerPlatformConfig displayManager);
    virtual ~DisplayManager() = default;

    bool apply() override;

private:
    fic::platform::SystemToolsPlatformConfig systemTools_;
    fic::platform::DisplayManagerPlatformConfig displayManager_;
};

#endif // DISPLAYMANAGER_H
