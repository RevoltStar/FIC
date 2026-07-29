#ifndef OSS_DISABLE_VIDEODISPLAY_WHEN_LOCKED_H
#define OSS_DISABLE_VIDEODISPLAY_WHEN_LOCKED_H

#include "modules/oss/submodules/DisplayManager.h"
class OSS_disable_videodisplay_when_locked : public DisplayManager
{
public:
    OSS_disable_videodisplay_when_locked(
        const fic::platform::PlatformExecutableResolver& executables,
        const fic::platform::DisplayManagerPlatformConfig& displayManager);

    bool apply () override;
};

#endif // OSS_DISABLE_VIDEODISPLAY_WHEN_LOCKED_H
