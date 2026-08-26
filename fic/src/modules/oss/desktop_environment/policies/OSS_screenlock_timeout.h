#ifndef OSS_SCREENLOCK_TIMEOUT_H
#define OSS_SCREENLOCK_TIMEOUT_H

#include "modules/oss/desktop_environment/DesktopEnvironment.h"
#include "platform/PlatformExecutableResolver.h"

#include <string>
#include <vector>

class OSS_screenlock_timeout : public DesktopEnvironment
{
public:
    explicit OSS_screenlock_timeout(
        const fic::platform::PlatformExecutableResolver& executables);

    bool apply () override;

private:
    const fic::platform::PlatformExecutableResolver& executables_;
};

#endif // OSS_SCREENLOCK_TIMEOUT_H
