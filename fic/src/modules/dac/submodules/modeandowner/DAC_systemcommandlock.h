#ifndef DAC_SYSTEMCOMMANDLOCK_H
#define DAC_SYSTEMCOMMANDLOCK_H

//#include "function.h"
#include <map>
#include <sstream>
#include <vector>
#include "modules/dac/submodules/ModeAndOwner.h"

class DAC_systemcommandlock : public ModeAndOwner{

public:
    DAC_systemcommandlock();
    bool apply () override;
};
#endif // DAC_SYSTEMCOMMANDLOCK_H
