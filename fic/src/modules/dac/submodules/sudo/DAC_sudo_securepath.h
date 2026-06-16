#ifndef DAC_SUDO_SECUREPATH_H
#define DAC_SUDO_SECUREPATH_H

#include "modules/dac/submodules/Sudo.h"

//Настройка ограничения времени sudo
class DAC_sudo_securepath : public Sudo
{
public:
    DAC_sudo_securepath();
    ~DAC_sudo_securepath();
    bool apply () override;

};


#endif // DAC_SUDO_SECUREPATH_H
