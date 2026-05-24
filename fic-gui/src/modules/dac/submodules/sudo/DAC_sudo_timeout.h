#ifndef DAC_SUDO_TIMEOUT_H
#define DAC_SUDO_TIMEOUT_H

#include "modules/dac/submodules/Sudo.h"

//Настройка ограничения времени sudo
class DAC_sudo_timeout : public Sudo
{
public:
    DAC_sudo_timeout();
    ~DAC_sudo_timeout();
    bool check_and_fix () override;
};

#endif // DAC_SUDO_TIMEOUT_H
