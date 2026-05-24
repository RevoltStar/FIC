#ifndef OSS_DISABLE_AUTOLOGIN_H
#define OSS_DISABLE_AUTOLOGIN_H

#include "modules/oss/submodules/DisplayManager.h"
#include "utils/SectionConfigFileHandler.h"

class OSS_disable_autologin : public DisplayManager
{
public:
    OSS_disable_autologin();

    bool check_and_fix () override;
};

#endif // OSS_DISABLE_AUTOLOGIN_H
