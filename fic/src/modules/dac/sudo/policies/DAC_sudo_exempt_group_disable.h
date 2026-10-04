#ifndef DAC_SUDO_EXEMPT_GROUP_DISABLE_H
#define DAC_SUDO_EXEMPT_GROUP_DISABLE_H

#include "modules/dac/sudo/Sudo.h"

// Запрет exempt_group.
//
// Desired global state: `Defaults !exempt_group` in the FIC-owned managed
// file (/etc/sudoers.d/zzzz-fic on every current platform profile).
//
// This policy is the SINGLE owner of the exempt_group security state.
// sudo_require_authentication deliberately no longer rewrites
// `exempt_group=...` itself: two independent mutation owners of one security
// state would mean two different rollback provenances for the same guarantee.
//
// Requires sudo_disable_scoped_defaults: a contextual
// `Defaults:alice exempt_group=...` / `Defaults!/cmd exempt_group=...` would
// otherwise silently reintroduce the bypass.
class DAC_sudo_exempt_group_disable : public Sudo
{
public:
    explicit DAC_sudo_exempt_group_disable(
        const fic::platform::SudoPlatformConfig& platformConfig,
        const fic::platform::PlatformExecutableResolver& executables);
    ~DAC_sudo_exempt_group_disable();
    bool apply() override;
};

#endif // DAC_SUDO_EXEMPT_GROUP_DISABLE_H
