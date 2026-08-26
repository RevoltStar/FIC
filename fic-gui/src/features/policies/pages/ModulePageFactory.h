#ifndef MODULE_PAGE_FACTORY_H
#define MODULE_PAGE_FACTORY_H

#include <vector>

#include "features/policies/models/ModuleDescriptor.h"
#include "features/policies/models/PolicyDescriptor.h"

class QWidget;

class ModulePageFactory
{
public:
    QWidget* create(const ModuleDescriptor& module,
                    const std::vector<PolicyDescriptor>& policies,
                    QWidget* parent = nullptr) const;
};

#endif // MODULE_PAGE_FACTORY_H
