#ifndef OSS_LOCK_ON_TTY_SWITCH_H
#define OSS_LOCK_ON_TTY_SWITCH_H

#include "modules/oss/submodules/DisplayManager.h"
#include "utils/SectionConfigFileHandler.h"

/*Блокировка графической сессии при переключении консоли*/
class OSS_lock_on_tty_switch : public DisplayManager
{
public:
    OSS_lock_on_tty_switch();

    bool check_and_fix () override;
};

#endif // OSS_LOCK_ON_TTY_SWITCH_H
