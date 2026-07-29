#ifndef DAC_SYSTEMCOMMANDLOCK_H
#define DAC_SYSTEMCOMMANDLOCK_H

//#include "function.h"
#include <map>
#include <sstream>
#include <vector>
#include "modules/dac/submodules/ModeAndOwner.h"
#include "platform/PlatformProfile.h"

class DAC_systemcommandlock : public ModeAndOwner{

public:
    explicit DAC_systemcommandlock(
        const fic::platform::DacPlatformConfig& platformConfig);
    bool apply () override;
};
#endif // DAC_SYSTEMCOMMANDLOCK_H
