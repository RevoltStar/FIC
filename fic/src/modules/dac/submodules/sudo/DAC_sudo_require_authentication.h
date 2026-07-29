#ifndef DAC_SUDO_REQUIRE_AUTHENTICATION_H
#define DAC_SUDO_REQUIRE_AUTHENTICATION_H

#include "modules/dac/submodules/Sudo.h"

class DAC_sudo_require_authentication : public Sudo {
public:
    explicit DAC_sudo_require_authentication(
        const fic::platform::SudoPlatformConfig& platformConfig,
        const fic::platform::PlatformExecutableResolver& executables);
    bool apply() override;
};

#endif // DAC_SUDO_REQUIRE_AUTHENTICATION_H
