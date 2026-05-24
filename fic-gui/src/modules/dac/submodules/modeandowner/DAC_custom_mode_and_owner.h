#ifndef DAC_CUSTOM_MODE_AND_OWNER_H
#define DAC_CUSTOM_MODE_AND_OWNER_H

#include "modules/dac/submodules/ModeAndOwner.h"

class DAC_custom_mode_and_owner : public ModeAndOwner
{
public:
    DAC_custom_mode_and_owner();
    bool check_and_fix() override;
};

#endif // DAC_CUSTOM_MODE_AND_OWNER_H
