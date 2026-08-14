#ifndef AUDIT_LOG_LEVEL_H
#define AUDIT_LOG_LEVEL_H

#include "modules/audit/submodules/Logging.h"

class AUDIT_log_level : public AuditLogging
{
public:
    AUDIT_log_level();
    ~AUDIT_log_level() override = default;

    bool apply() override;
};

#endif // AUDIT_LOG_LEVEL_H
