#ifndef AUDIT_LOGGING_H
#define AUDIT_LOGGING_H

#include "modules/audit/AUDIT.h"

class AuditLogging : public Audit
{
public:
    AuditLogging();
    ~AuditLogging() override = default;
};

#endif // AUDIT_LOGGING_H
