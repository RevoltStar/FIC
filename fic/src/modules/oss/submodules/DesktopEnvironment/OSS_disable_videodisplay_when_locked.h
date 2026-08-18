#ifndef OSS_DISABLE_VIDEODISPLAY_WHEN_LOCKED_H
#define OSS_DISABLE_VIDEODISPLAY_WHEN_LOCKED_H

#include "modules/oss/submodules/DesktopEnvironment.h"
#include "platform/PlatformExecutableResolver.h"

class OSS_disable_videodisplay_when_locked : public DesktopEnvironment
{
public:
    explicit OSS_disable_videodisplay_when_locked(
        const fic::platform::PlatformExecutableResolver& executables);

    bool apply() override;

private:
    const fic::platform::PlatformExecutableResolver& executables_;
};

#endif // OSS_DISABLE_VIDEODISPLAY_WHEN_LOCKED_H