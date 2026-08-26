#include "features/policies/pages/ModulePageFactory.h"

#include "features/policies/pages/AuditModulePage.h"
#include "features/devices/pages/DeviceModulePage.h"
#include "features/policies/pages/StandardModulePage.h"

QWidget* ModulePageFactory::create(
    const ModuleDescriptor& module,
    const std::vector<PolicyDescriptor>& policies,
    QWidget* parent) const
{
    switch (module.view) {
    case ModuleView::Standard:
        return new StandardModulePage(module.name, policies, parent);
    case ModuleView::Device:
        return new DeviceModulePage(module.name, policies, parent);
    case ModuleView::Audit:
        return new AuditModulePage(module.name, policies, parent);
    }
    return nullptr;
}
