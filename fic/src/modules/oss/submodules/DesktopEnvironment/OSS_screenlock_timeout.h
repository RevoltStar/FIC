#ifndef OSS_SCREENLOCK_TIMEOUT_H
#define OSS_SCREENLOCK_TIMEOUT_H

#include "modules/oss/submodules/DesktopEnvironment.h"

class OSS_screenlock_timeout : public DesktopEnvironment
{
public:
    OSS_screenlock_timeout();

    bool check_and_fix () override;
};

#endif // OSS_SCREENLOCK_TIMEOUT_H
