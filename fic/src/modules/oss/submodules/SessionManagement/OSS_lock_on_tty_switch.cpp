#include "modules/oss/submodules/SessionManagement/OSS_lock_on_tty_switch.h"

#include <fic/core/LocalizationManager.h>

OSS_lock_on_tty_switch::OSS_lock_on_tty_switch()
    : SessionManagement()
{
    this->policyName = "lock_on_tty_switch";
    this->policyTypeValue = std::make_unique<FixedPolicyTypeValue>();
}

bool OSS_lock_on_tty_switch::apply()
{
    this->log(
        LocalizationManager::getLang(
            "[module:OSS][policy:lock_on_tty_switch][message:not_implemented]"
        ),
        logLevel::ERROR
    );
    return false;
}
