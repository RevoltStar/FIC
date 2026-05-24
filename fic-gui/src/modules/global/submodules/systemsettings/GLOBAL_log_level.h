#ifndef GLOBAL_LOG_LEVEL_H
#define GLOBAL_LOG_LEVEL_H

#include "modules/global/submodules/SystemSettings.h"
#include "utils/Logger.h"

class GLOBAL_log_level : public SystemSettings
{
public:
    GLOBAL_log_level();
    virtual ~GLOBAL_log_level() = default;

    bool check_and_fix() override;
};

#endif // GLOBAL_LOG_LEVEL_H
