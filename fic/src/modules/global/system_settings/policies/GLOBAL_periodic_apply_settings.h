#ifndef GLOBAL_PERIODIC_APPLY_SETTINGS_H
#define GLOBAL_PERIODIC_APPLY_SETTINGS_H
#include "modules/global/system_settings/SystemSettings.h"

class GLOBAL_check_interval : public SystemSettings {
public:
    GLOBAL_check_interval();
    bool apply() override;
};
class GLOBAL_periodic_apply_min_pause : public SystemSettings {
public:
    GLOBAL_periodic_apply_min_pause();
    bool apply() override;
};
#endif
