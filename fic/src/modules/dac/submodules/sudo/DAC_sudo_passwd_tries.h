#ifndef DAC_SUDO_PASSWD_TRIES_H
#define DAC_SUDO_PASSWD_TRIES_H

#include "modules/dac/submodules/Sudo.h"
//Настройка ограничения времени sudo
class DAC_sudo_passwd_tries : public Sudo
{
public:
    DAC_sudo_passwd_tries();
    ~DAC_sudo_passwd_tries();
    bool check_and_fix () override;
};

#endif // DAC_SUDO_PASSWD_TRIES_H
