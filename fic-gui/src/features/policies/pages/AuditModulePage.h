#ifndef AUDIT_MODULE_PAGE_H
#define AUDIT_MODULE_PAGE_H

#include <string>
#include <vector>

#include <QWidget>

#include "features/policies/models/PolicyDescriptor.h"

class AuditModulePage : public QWidget
{
public:
    AuditModulePage(const std::string& module,
                    const std::vector<PolicyDescriptor>& policies,
                    QWidget* parent = nullptr);
};

#endif // AUDIT_MODULE_PAGE_H
