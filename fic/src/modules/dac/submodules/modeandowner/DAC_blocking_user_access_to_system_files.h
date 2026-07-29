#ifndef DAC_BLOCKING_USER_ACCESS_TO_SYSTEM_FILES_H
#define DAC_BLOCKING_USER_ACCESS_TO_SYSTEM_FILES_H
#include <iostream>
#include <fstream>
#include <map>
#include <vector>

#include "modules/dac/submodules/ModeAndOwner.h"
#include "platform/PlatformProfile.h"

class DAC_blocking_user_access_to_system_files : public ModeAndOwner
{
public:
     explicit DAC_blocking_user_access_to_system_files(
         const fic::platform::DacPlatformConfig& platformConfig);
     bool apply () override;

};

#endif // DAC_BLOCKING_USER_ACCESS_TO_SYSTEM_FILES_H
