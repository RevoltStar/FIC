#ifndef OSS_DISABLE_VIDEODISPLAY_WHEN_LOCKED_H
#define OSS_DISABLE_VIDEODISPLAY_WHEN_LOCKED_H

#include "modules/oss/submodules/DisplayManager.h"
#include "utils/SectionConfigFileHandler.h"
class OSS_disable_videodisplay_when_locked : public DisplayManager
{
public:
    OSS_disable_videodisplay_when_locked();

    bool check_and_fix () override;
};

#endif // OSS_DISABLE_VIDEODISPLAY_WHEN_LOCKED_H

