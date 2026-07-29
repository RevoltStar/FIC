#ifndef DAC_SUDO_SECUREPATH_H
#define DAC_SUDO_SECUREPATH_H

#include "modules/dac/submodules/Sudo.h"

//Настройка ограничения времени sudo
class DAC_sudo_securepath : public Sudo
{
public:
    explicit DAC_sudo_securepath(
        const fic::platform::SudoPlatformConfig& platformConfig,
        const fic::platform::PlatformExecutableResolver& executables);
    ~DAC_sudo_securepath();
    bool apply () override;

};


#endif // DAC_SUDO_SECUREPATH_H
