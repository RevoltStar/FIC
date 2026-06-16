#include "modules/oss/submodules/SessionManagement/OSS_lock_on_tty_switch.h"

OSS_lock_on_tty_switch::OSS_lock_on_tty_switch()
    : SessionManagement()
{
    this->policyName = "lock_on_tty_switch";
    this->policyTypeValue = std::make_unique<FixedPolicyTypeValue>();
}

bool OSS_lock_on_tty_switch::apply()
{
    return true;
}
