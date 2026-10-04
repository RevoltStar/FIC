#ifndef DAC_SUDO_DISABLE_SCOPED_DEFAULTS_H
#define DAC_SUDO_DISABLE_SCOPED_DEFAULTS_H

#include "modules/dac/sudo/Sudo.h"

#include <vector>

// Запрет контекстных перегрузок Defaults.
//
// Forbids ALL FOUR scoped sudoers Defaults forms:
//
//   Defaults:user ...    Defaults@host ...
//   Defaults>runas ...   Defaults!command ...
//
// FIC does NOT compute whether a scoped entry actually applies to a given
// user/host/command: no User_Alias/Host_Alias/Runas_Alias/Cmnd_Alias
// resolution, no %group/netgroup expansion, no `ALL,!foo` negation. The mere
// PRESENCE of an active scoped Defaults is the violation. That is what keeps
// this decidable without building a sudoers semantic engine.
//
// A global `Defaults !exempt_group` cannot universally cancel a scoped entry,
// so the offending foreign entries are temporarily deactivated through the
// FIC-owned wrapper model (see SudoersDisabledWrapper.h).
class DAC_sudo_disable_scoped_defaults : public Sudo
{
public:
    explicit DAC_sudo_disable_scoped_defaults(
        const fic::platform::SudoPlatformConfig& platformConfig,
        const fic::platform::PlatformExecutableResolver& executables);
    ~DAC_sudo_disable_scoped_defaults();
    bool apply() override;
};

#endif // DAC_SUDO_DISABLE_SCOPED_DEFAULTS_H
