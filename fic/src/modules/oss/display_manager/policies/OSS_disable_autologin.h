#ifndef OSS_DISABLE_AUTOLOGIN_H
#define OSS_DISABLE_AUTOLOGIN_H

#include "modules/oss/display_manager/DisplayManager.h"

class OSS_disable_autologin : public DisplayManager
{
public:
    OSS_disable_autologin(
        const fic::platform::PlatformExecutableResolver& executables,
        const fic::platform::DisplayManagerPlatformConfig& displayManager);

    bool apply () override;
};

#endif // OSS_DISABLE_AUTOLOGIN_H
