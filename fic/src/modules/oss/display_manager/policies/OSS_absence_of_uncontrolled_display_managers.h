#ifndef FIC_ABSENCE_UNCONTROLLED_DM_H
#define FIC_ABSENCE_UNCONTROLLED_DM_H
#include "modules/oss/display_manager/policies/OSS_controlled_display_managers.h"
class OSS_absence_of_uncontrolled_display_managers final : public DisplayManager {
public:
    OSS_absence_of_uncontrolled_display_managers(ControlledDisplayManagerScope&,std::shared_ptr<DisplayManagerInventory>);
    bool apply() override;
    bool evaluate(const DisplayManagerSnapshot&,std::string& error);
private:
    ControlledDisplayManagerScope& scope_;
    std::shared_ptr<DisplayManagerInventory> inventory_;
};
#endif
