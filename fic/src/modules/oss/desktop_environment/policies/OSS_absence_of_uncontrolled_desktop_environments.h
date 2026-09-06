#ifndef OSS_ABSENCE_OF_UNCONTROLLED_DESKTOP_ENVIRONMENTS_H
#define OSS_ABSENCE_OF_UNCONTROLLED_DESKTOP_ENVIRONMENTS_H

#include "modules/oss/desktop_environment/DesktopEnvironment.h"
#include "modules/oss/desktop_environment/DesktopEnvironmentControl.h"

#include <memory>

class OSS_absence_of_uncontrolled_desktop_environments final
    : public DesktopEnvironment,
      public SessionInventoryCompliancePolicy {
public:
    OSS_absence_of_uncontrolled_desktop_environments(
        ControlledDesktopEnvironmentScope& scope,
        std::shared_ptr<GraphicalSessionInventory> inventory);

    bool apply() override;
    bool evaluateSessionInventory(
        const std::vector<ClassifiedGraphicalSession>& sessions,
        std::string& error) override;
    std::vector<PolicyCapability> capabilities() const override {
        return {PolicyCapability::SessionInventoryCompliance};
    }

private:
    ControlledDesktopEnvironmentScope& scope_;
    std::shared_ptr<GraphicalSessionInventory> inventory_;
};

#endif // OSS_ABSENCE_OF_UNCONTROLLED_DESKTOP_ENVIRONMENTS_H
