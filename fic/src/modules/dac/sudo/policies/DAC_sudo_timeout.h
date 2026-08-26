#ifndef DAC_SUDO_TIMEOUT_H
#define DAC_SUDO_TIMEOUT_H

#include "modules/dac/sudo/Sudo.h"

//Настройка ограничения времени sudo
class DAC_sudo_timeout : public Sudo
{
public:
    explicit DAC_sudo_timeout(
        const fic::platform::SudoPlatformConfig& platformConfig,
        const fic::platform::PlatformExecutableResolver& executables);
    ~DAC_sudo_timeout();
    bool apply () override;
};

#endif // DAC_SUDO_TIMEOUT_H
