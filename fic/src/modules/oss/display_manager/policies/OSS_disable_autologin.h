#ifndef OSS_DISABLE_AUTOLOGIN_H
#define OSS_DISABLE_AUTOLOGIN_H
#include "modules/oss/display_manager/policies/OSS_controlled_display_managers.h"
class OSS_disable_autologin final : public DisplayManager {
public:
    OSS_disable_autologin(ControlledDisplayManagerScope&,std::shared_ptr<DisplayManagerInventory>,
        std::shared_ptr<DisplayManagerConfigTransaction>,fic::rollback::MutationJournal* journal=nullptr);
    bool apply() override;
    const std::string& reconciliationError() const { return reconciliationError_; }
private:
    std::string reconciliationError_;
    ControlledDisplayManagerScope& scope_;
    std::shared_ptr<DisplayManagerInventory> inventory_;
    std::shared_ptr<DisplayManagerConfigTransaction> backend_;
    fic::rollback::MutationJournal* journal_;
};
#endif
