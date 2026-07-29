#ifndef OSS_SCREENLOCK_TIMEOUT_H
#define OSS_SCREENLOCK_TIMEOUT_H

#include "modules/oss/submodules/DesktopEnvironment.h"
#include "platform/PlatformProfile.h"

#include <string>
#include <vector>

class OSS_screenlock_timeout : public DesktopEnvironment
{
public:
    explicit OSS_screenlock_timeout(
        const fic::platform::SystemToolsPlatformConfig& systemTools);

    bool apply () override;

private:
    std::vector<std::string> loginctlCandidates_;
};

#endif // OSS_SCREENLOCK_TIMEOUT_H
