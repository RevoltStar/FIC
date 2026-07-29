#ifndef DAC_SUDO_ENV_RESET_H
#define DAC_SUDO_ENV_RESET_H

#include "modules/dac/submodules/Sudo.h"

// Настройка сброса переменных окружения для sudo
class DAC_sudo_env_reset : public Sudo
{
public:
    explicit DAC_sudo_env_reset(
        const fic::platform::SudoPlatformConfig& platformConfig,
        const fic::platform::PlatformExecutableResolver& executables);
    ~DAC_sudo_env_reset();
    bool apply() override;
};

#endif // DAC_SUDO_ENV_RESET_H
