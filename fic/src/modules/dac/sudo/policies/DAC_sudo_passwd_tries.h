#ifndef DAC_SUDO_PASSWD_TRIES_H
#define DAC_SUDO_PASSWD_TRIES_H

#include "modules/dac/sudo/Sudo.h"
//Настройка ограничения времени sudo
class DAC_sudo_passwd_tries : public Sudo
{
public:
    explicit DAC_sudo_passwd_tries(
        const fic::platform::SudoPlatformConfig& platformConfig,
        const fic::platform::PlatformExecutableResolver& executables);
    ~DAC_sudo_passwd_tries();
    bool apply () override;
};

#endif // DAC_SUDO_PASSWD_TRIES_H
