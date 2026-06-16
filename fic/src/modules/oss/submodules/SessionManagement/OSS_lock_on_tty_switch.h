#ifndef OSS_LOCK_ON_TTY_SWITCH_H
#define OSS_LOCK_ON_TTY_SWITCH_H

#include "modules/oss/submodules/SessionManagement.h"

class OSS_lock_on_tty_switch : public SessionManagement
{
public:
    OSS_lock_on_tty_switch();

    bool apply() override;
};

#endif // OSS_LOCK_ON_TTY_SWITCH_H
